#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""E16 execution-surface qualification: owned live runner and verifier.

E16 asks whether discovery finds, or honestly refuses, PKCS#11 code in
non-standard shapes. The six fixtures under tests/fixtures/e16 (plus the
reviewed live-discovery provider as control) are run under the single hold
protocol of tests/fixtures/e16/e16_protocol.h, and a frozen observer binary
measures them. Two campaigns exist:

- ``hinted``: one owned cell per surface, ``profile --pid <driver> --module
  <object>``. Supported shapes must be counted exactly at the executed
  endpoint; direct exports must be refused by an explicit no-table record
  bound to the owned object; anonymous JIT code must stay unattributed and
  the capture PARTIAL (a documented boundary, not a refusal record).
- ``system-mixed``: every surface plus a foreign-traffic driver at once,
  under one unhinted ``profile --system``. Owned counts come only from the
  pinned physical endpoint; the foreign driver's calls (byte-identical
  provider, different inode) must be observed as foreign and never as owned.

Authority, in order. The fixture's ready line names the exact endpoint
address; before GO the runner pins that mapping through the shared receipt
helper (``scripts/system-scope-receipt.py``: map_files pin, birth and
namespace bracketing, mountinfo device bridge). Report rows are matched by
the receipt's joined identity and the endpoint's file offset, never by a
pathname or a function name. The observer is a frozen private copy whose
digest, embedded BPF objects and source revision are bound by a provenance
manifest written beforehand from a clean checkout. Evidence lives in a new
private directory created only after every ancestor is proven trusted
(``src/output.rs`` rules). Each process outcome is kept separately; a
signal, timeout, nonzero exit or failed cleanup is never folded into zero.
Missing, ambiguous or contradictory evidence is UNKNOWN.

Usage:
  python3 -I scripts/qualify-e16-surfaces.py --self-test
  python3 -I scripts/qualify-e16-surfaces.py provenance --observer BIN \\
      --bpf-object OBJ [--bpf-object OBJ ...] --out MANIFEST
  sudo -n flock LOCK python3 -I scripts/qualify-e16-surfaces.py run \\
      --campaign hinted|system-mixed --observer BIN --provenance MANIFEST \\
      --artifacts NEW_PRIVATE_DIR
  python3 -I scripts/qualify-e16-surfaces.py verify --artifacts DIR

``run`` needs root (map_files pins and BPF); ``provenance`` must run as the
unprivileged checkout owner; ``verify`` and ``--self-test`` are
unprivileged. The self-test exercises the reducers and the real fixtures
under the hold protocol with mirrored /proc receipts; it never runs the
observer, so a passing self-test is not a live result.
"""

import argparse
import hashlib
import json
import os
import pwd
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
import _loader  # noqa: E402

SCHEMA = "p11scope/e16-qualification/v2"
PROVENANCE_SCHEMA = "p11scope/e16-observer-provenance/v1"
ANONYMOUS_SCHEMA = "p11scope/e16-anonymous-mapping-receipt/v1"
PROFILE_SCHEMA = "p11scope/observed-profile/v3"
# Internal diagnostic vocabulary (scan.rs NO_TABLE_FOUND_MARKER) and its
# finite public projection (render.rs TABLE_UNAVAILABLE).
NO_TABLE_DIAGNOSTIC = "no function table was found in its file-backed data"
TABLE_UNAVAILABLE = "function table unavailable in file-backed data"
JIT_BOUNDARY = ("anonymous executable memory is outside the file-backed candidate "
                "universe; calls into it are neither discovered nor attributed")
OPERATOR_COMMAND = ("sudo", "-n", "flock", "/var/tmp/p11scope-ws-tmp/privileged.lock",
                    "python3", "-I", "scripts/qualify-e16-surfaces.py", "run")

MAX_TRANSCRIPT = 256 * 1024
MAX_LINE = 4096
MAX_CAPTURE = 64 * 1024 * 1024
MAX_OBSERVER_LOG = 8 * 1024 * 1024
READY_LINE = re.compile(
    r"^p11scope: capturing: (0|[1-9][0-9]*) probe\(s\) attached; stop with Ctrl-C$")
DRIVER_READY = re.compile(
    r"^P11SCOPE_E16 ready pid=([1-9][0-9]*) starttime=([1-9][0-9]*) "
    r"endpoint=0x([0-9a-f]+) image=0x([0-9a-f]+) calls=([1-9][0-9]*)$")
DRIVER_CALL = re.compile(r"^P11SCOPE_E16 call (\S+) (0|[1-9][0-9]*) rv=(0|[1-9][0-9]*)$")
DRIVER_DONE = re.compile(r"^P11SCOPE_E16 done calls=([1-9][0-9]*)$")
DRIVER_WITNESS = re.compile(r"^P11SCOPE_E16 provider [a-z]+ [A-Za-z0-9_]+$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

FIXTURE_SOURCES = (
    "tests/fixtures/live-discovery-provider.c",
    "tests/fixtures/e16/e16_protocol.h",
    "tests/fixtures/e16/e16_driver.c",
    "tests/fixtures/e16/e16_static_driver.c",
    "tests/fixtures/e16/e16_static_provider.c",
    "tests/fixtures/e16/e16_jit_driver.c",
    "tests/fixtures/e16/e16_direct_exports.c",
    "tests/fixtures/e16/e16_vendor_only.c",
    "tests/fixtures/e16/e16_hsm_proxy.c",
)
# Everything this runner executes or imports as authority. The provenance
# manifest binds their bytes to the observer's source revision.
BOUND_SOURCES = (
    "scripts/qualify-e16-surfaces.py",
    "scripts/_loader.py",
    "scripts/system-scope-receipt.py",
    "scripts/system-scope-measure.py",
    "scripts/check-capture-evidence.py",
) + FIXTURE_SOURCES
REQUIRED_BPF_OBJECTS = ("p11scope-ebpf",)

# name -> how the fixture runs. `hint` is the build artifact named by
# `--module`; `endpoint` is "file" (pinned through map_files) or
# "anonymous"; `ordinal` is the table position executed, when any.
SURFACES = {
    "control": {"expect": "supported", "hint": "control.so", "label": "table[0]", "ordinal": 0,
                "endpoint": "file",
                "argv": ("driver", "table", "@control.so", "C_GetFunctionList", "0", "@calls")},
    "proxy": {"expect": "supported", "hint": "proxy.so", "label": "table[0]", "ordinal": 0,
              "endpoint": "file",
              "argv": ("driver", "table", "@proxy.so", "C_GetFunctionList", "0", "@calls")},
    "static": {"expect": "supported", "hint": "static-driver", "label": "table[0]", "ordinal": 0,
               "endpoint": "file", "argv": ("static-driver", "@calls")},
    "vendor": {"expect": "supported", "hint": "vendor.so", "label": "table[0]", "ordinal": 0,
               "endpoint": "file",
               "argv": ("driver", "table", "@vendor.so", "Vendor_GetFunctionList", "0",
                        "@calls")},
    "direct-no-table": {"expect": "explicit-unsupported", "hint": "direct.so",
                        "label": "C_GenerateRandom", "ordinal": None, "endpoint": "file",
                        "argv": ("driver", "call", "@direct.so", "C_GenerateRandom", "@calls")},
    "anonymous-jit": {"expect": "bounded-unsupported", "hint": "jit-driver",
                      "label": "jit_trampoline", "ordinal": None, "endpoint": "anonymous",
                      "argv": ("jit-driver", "@calls")},
}
FOREIGN = {"expect": "foreign", "hint": "foreign.so", "label": "table[0]", "ordinal": 0,
           "endpoint": "file",
           "argv": ("driver", "table", "@foreign.so", "C_GetFunctionList", "0", "@foreign_calls")}
CELL_ORDER = ("control", "proxy", "static", "vendor", "direct-no-table", "anonymous-jit")
CAMPAIGNS = {
    "hinted": {"mode": "pid-hinted", "foreign": False},
    "system-mixed": {"mode": "system-unhinted", "foreign": True},
}


class Unknown(ValueError):
    """Qualification evidence is absent, contradictory or incomplete."""


def require(condition, message):
    if not condition:
        raise Unknown(message)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_path(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def helpers():
    """The shared seams this runner builds on, loaded as fresh modules."""
    return types.SimpleNamespace(
        receipt=_loader.load_sibling("system-scope-receipt.py"),
        measure=_loader.load_sibling("system-scope-measure.py"),
        capture=_loader.load_sibling("check-capture-evidence.py"),
    )


# --------------------------------------------------------------------------
# H8: private evidence under a proven-trusted ancestry, created exclusively.
# --------------------------------------------------------------------------

def sudo_uid(environ, euid):
    """SUDO_UID trusted exactly as src/output.rs sudo_uid() trusts it."""
    if euid != 0:
        return None
    value = environ.get("SUDO_UID", "")
    if not value.isascii() or not value.isdigit():
        return None
    uid = int(value)
    if uid == 0 or uid >= 2**32 - 1:
        return None
    try:
        pwd.getpwuid(uid)
    except KeyError:
        return None
    return uid


def check_trusted_directory(fd, label, euid, trusted_sudo_uid):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode), f"{label} is not a directory")
    mode = stat.S_IMODE(info.st_mode)
    require(not mode & 0o022 or mode & stat.S_ISVTX,
            f"{label} is writable by group or others without the sticky bit "
            f"(mode {mode:04o})")
    owner_trusted = (info.st_uid in (euid, 0)
                     or (trusted_sudo_uid is not None and info.st_uid == trusted_sudo_uid))
    require(owner_trusted, f"{label} is owned by untrusted uid {info.st_uid}")


DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class PrivateDir:
    """One exclusively created private directory, addressed by descriptor."""

    def __init__(self, path, fd):
        self.path = Path(path)
        self.fd = fd

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def child_path(self, name):
        require("/" not in name and name not in ("", ".", ".."), f"bad artifact name {name!r}")
        return self.path / name

    def subdir(self, name):
        self.child_path(name)
        os.mkdir(name, 0o700, dir_fd=self.fd)
        fd = os.open(name, DIRECTORY_FLAGS, dir_fd=self.fd)
        return PrivateDir(self.path / name, fd)

    def create(self, name, mode=0o600):
        self.child_path(name)
        return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       mode, dir_fd=self.fd)

    def write_bytes(self, name, data, mode=0o600):
        fd = self.create(name, mode)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def write_json(self, name, value):
        self.write_bytes(name, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def create_private_root(path, *, euid=None, environ=None):
    """Validate every ancestor without following links, then mkdir 0700.

    Nothing is created, chmod-ed or resolved before every ancestor passed.
    An existing final directory is refused rather than reused or repaired.
    """
    euid = os.geteuid() if euid is None else euid
    environ = os.environ if environ is None else environ
    trusted_sudo = sudo_uid(environ, euid)
    text = os.fspath(path)
    require(text.startswith("/"), "artifact directory must be an absolute path")
    parts = [part for part in text.split("/") if part]
    require(parts and all(part not in (".", "..") for part in parts),
            "artifact directory must be a normalized absolute path")
    fd = os.open("/", DIRECTORY_FLAGS)
    try:
        check_trusted_directory(fd, "/", euid, trusted_sudo)
        current = ""
        for part in parts[:-1]:
            current += "/" + part
            try:
                next_fd = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
            except OSError as error:
                raise Unknown(f"artifact ancestor {current} is not a plain directory: "
                              f"{error.strerror}") from error
            os.close(fd)
            fd = next_fd
            check_trusted_directory(fd, f"artifact ancestor {current}", euid, trusted_sudo)
        try:
            os.mkdir(parts[-1], 0o700, dir_fd=fd)
        except FileExistsError as error:
            raise Unknown("artifact directory already exists; it is never reused or "
                          "re-permissioned") from error
        root_fd = os.open(parts[-1], DIRECTORY_FLAGS, dir_fd=fd)
    finally:
        os.close(fd)
    info = os.fstat(root_fd)
    if info.st_uid != euid or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(root_fd)
        raise Unknown("created artifact directory is not owner-only 0700")
    return PrivateDir("/" + "/".join(parts), root_fd)


# --------------------------------------------------------------------------
# H4: bounded framed reads that cannot block past their deadline.
# --------------------------------------------------------------------------

class FramedReader:
    """Nonblocking newline framing with byte, line and absolute-time bounds.

    Every byte read is retained in ``transcript`` so a failed protocol keeps
    its partial evidence.
    """

    def __init__(self, fd, *, max_bytes=MAX_TRANSCRIPT, max_line=MAX_LINE):
        os.set_blocking(fd, False)
        self.fd = fd
        self.max_bytes = max_bytes
        self.max_line = max_line
        self.buffer = bytearray()
        self.transcript = bytearray()
        self.eof = False

    def _fill(self, deadline):
        remaining = deadline - time.monotonic()
        require(remaining > 0, "deadline expired before the expected line")
        poller = select.poll()
        poller.register(self.fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if not poller.poll(max(1, int(remaining * 1000))):
            return
        try:
            chunk = os.read(self.fd, 65536)
        except (BlockingIOError, InterruptedError):
            return
        if not chunk:
            self.eof = True
            return
        require(len(self.transcript) + len(chunk) <= self.max_bytes,
                f"transcript exceeds its {self.max_bytes}-byte bound")
        self.transcript += chunk
        self.buffer += chunk

    def read_line(self, deadline):
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                require(newline <= self.max_line, f"line exceeds its {self.max_line}-byte bound")
                line = bytes(self.buffer[:newline])
                del self.buffer[:newline + 1]
                try:
                    return line.decode("utf-8")
                except UnicodeError as error:
                    raise Unknown("line is not UTF-8") from error
            require(len(self.buffer) <= self.max_line,
                    f"line exceeds its {self.max_line}-byte bound")
            if self.eof:
                raise Unknown("EOF inside a partial line" if self.buffer
                              else "EOF before the expected line")
            self._fill(deadline)

    def drain(self, deadline):
        """Retain whatever remains, up to EOF or the deadline."""
        try:
            while not self.eof and time.monotonic() < deadline:
                self._fill(deadline)
        except Unknown:
            pass


# --------------------------------------------------------------------------
# Driver protocol and ledger (pure: from the exact retained bytes).
# --------------------------------------------------------------------------

def next_protocol_line(reader, deadline):
    """The next protocol line; provider witness lines carry no protocol."""
    while True:
        line = reader.read_line(deadline)
        if not DRIVER_WITNESS.fullmatch(line):
            return line


def parse_ready(line):
    match = DRIVER_READY.fullmatch(line)
    require(match is not None, f"malformed ready line: {line!r}")
    return {"pid": int(match[1]), "starttime": int(match[2]), "endpoint": int(match[3], 16),
            "image": int(match[4], 16), "calls": int(match[5])}


def parse_ledger(transcript, *, label, calls):
    """The independent fixture ledger, re-derived from the retained bytes."""
    require(isinstance(transcript, (bytes, bytearray)) and transcript.endswith(b"\n"),
            "driver transcript is empty or ends inside a partial line")
    try:
        lines = bytes(transcript).decode("utf-8").split("\n")[:-1]
    except UnicodeError as error:
        raise Unknown("driver transcript is not UTF-8") from error
    protocol = [line for line in lines if not DRIVER_WITNESS.fullmatch(line)]
    require(protocol, "driver transcript has no protocol lines")
    ready = parse_ready(protocol[0])
    require(ready["calls"] == calls, f"driver announced {ready['calls']} calls, wanted {calls}")
    body = protocol[1:]
    require(len(body) == calls + 1,
            f"driver ledger has {len(body)} records after ready, wanted {calls + 1}")
    for index, line in enumerate(body[:-1]):
        match = DRIVER_CALL.fullmatch(line)
        require(match is not None, f"malformed call record: {line!r}")
        require(match[1] == label and int(match[2]) == index and match[3] == "0",
                f"call record {index} is not `{label} {index} rv=0`: {line!r}")
    done = DRIVER_DONE.fullmatch(body[-1])
    require(done is not None and int(done[1]) == calls,
            f"driver ledger is not closed by done calls={calls}: {body[-1]!r}")
    return {"ready": ready, "entered": calls, "returned": calls,
            "witnesses": len(lines) - len(protocol)}


# --------------------------------------------------------------------------
# H2: pre-GO receipts and the identity they authorize.
# --------------------------------------------------------------------------

def handshake_text(ready, address):
    return f"pid={ready['pid']} starttime={ready['starttime']} endpoint=0x{address:x}\n"


def file_mapping_receipt(receipt_mod, proc_root, ready, address, expected_file, handshake):
    """Pin the executable mapping containing ``address`` through map_files.

    ``handshake`` must already hold ``handshake_text(ready, address)``.
    """
    args = types.SimpleNamespace(proc_root=str(proc_root), after_proc_root=None,
                                 handshake=str(handshake), expected_file=str(expected_file),
                                 source_file=None)
    try:
        receipt = receipt_mod.mapping_receipt(args)
        receipt_mod.report_identity_bridge(receipt)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise Unknown(f"mapping receipt refused: {error}") from error
    return receipt


def anonymous_mapping_receipt(receipt_mod, proc_root, ready, address):
    """Prove ``address`` executes from anonymous memory of one process birth."""
    pid = ready["pid"]
    try:
        birth = receipt_mod.read_birth(proc_root, pid)
        require(birth == ready["starttime"], "anonymous receipt PID birth does not match")
        maps_bytes, maps = receipt_mod.read_maps(proc_root, pid)
        mapping = receipt_mod.addressed_mapping(maps, address)
        require(receipt_mod.read_birth(proc_root, pid) == birth,
                "PID birth changed while reading the anonymous mapping")
    except (OSError, ValueError, KeyError) as error:
        raise Unknown(f"anonymous mapping receipt refused: {error}") from error
    require(mapping["ino"] == 0 and mapping["dev"] == [0, 0]
            and (mapping["path"] == "" or mapping["path"].startswith("[anon")),
            f"endpoint 0x{address:x} is not anonymous executable memory: {mapping}")
    return {"schema": ANONYMOUS_SCHEMA, "pid": pid, "starttime": birth,
            "endpoint_address": f"0x{address:x}",
            "mapping": {"start": f"0x{mapping['start']:x}", "end": f"0x{mapping['end']:x}",
                        "perms": mapping["perms"], "offset": f"0x{mapping['offset']:x}",
                        "dev": mapping["dev"], "ino": mapping["ino"], "path": mapping["path"]},
            "maps_sha256": sha256_bytes(maps_bytes)}


def owned_identity(helper, receipt):
    """The report-domain identity a map_files receipt authorizes, or UNKNOWN.

    Reports render ``dev`` in the maps domain while the digest comes from
    the opened object; only the receipt's validated bridge joins them.
    """
    try:
        bridge = helper.receipt.report_identity_bridge(receipt)
        candidate = {"dev": receipt["mapping_identity"]["dev"],
                     "ino": receipt["mapping_identity"]["ino"],
                     "sha256": receipt["opened_file_identity"]["sha256"],
                     "report_identity_associated": True,
                     "report_identity_bridge": bridge}
    except (KeyError, TypeError, ValueError) as error:
        raise Unknown(f"receipt identity bridge is invalid: {error}") from error
    joined = helper.measure._validated_report_identity_bridge(candidate)
    require(joined is not None, "receipt identity bridge does not join maps and opened file")
    dev, ino, sha = joined
    return {"dev": list(dev), "ino": ino, "sha256": sha}


def endpoint_file_offset(receipt):
    mapping = receipt["mapping"]
    endpoint = int(receipt["endpoint_address"], 16)
    start = int(mapping["start"], 16)
    end = int(mapping["end"], 16)
    require(start <= endpoint < end, "endpoint lies outside its receipt mapping")
    return endpoint - start + int(mapping["offset"], 16)


def receipt_still_holds(receipt_mod, proc_root, receipt):
    """Re-read the retained workload: same birth, same addressed mapping."""
    try:
        require(receipt_mod.read_birth(proc_root, receipt["pid"]) == receipt["starttime"],
                "workload birth changed before release")
        _, maps = receipt_mod.read_maps(proc_root, receipt["pid"])
        current = receipt_mod.addressed_mapping(maps, int(receipt["endpoint_address"], 16))
    except (OSError, ValueError, KeyError) as error:
        raise Unknown(f"retained workload mapping could not be re-read: {error}") from error
    recorded = receipt["mapping"]
    require(current["start"] == int(recorded["start"], 16)
            and current["end"] == int(recorded["end"], 16)
            and current["perms"] == recorded["perms"]
            and current["offset"] == int(recorded["offset"], 16)
            and current["dev"] == recorded["dev"] and current["ino"] == recorded["ino"],
            "addressed endpoint mapping changed before release")


def path_still_names_pin(receipt_mod, path, receipt):
    """A same-path replacement (even byte-identical) is not the mapped object."""
    try:
        current = receipt_mod.file_identity(path)
    except OSError as error:
        raise Unknown(f"fixture path no longer opens: {error}") from error
    pinned = receipt["opened_file_identity"]
    require(receipt_mod.physical(current) == receipt_mod.physical(pinned),
            f"{path} no longer names the mapped object")


# --------------------------------------------------------------------------
# H1/H6: reduce one capture by exact identity, offset and ordinal.
# --------------------------------------------------------------------------

def load_capture(helper, raw):
    require(raw, "observer wrote no capture")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Unknown(f"capture is not JSON: {error}") from error
    require(isinstance(document, dict) and document.get("schema") == PROFILE_SCHEMA,
            "capture is not an observed-profile v3 document")
    try:
        require(isinstance(document.get("functions"), list), "capture has no functions[]")
        helper.capture.exact_module_ownership(document)
        for item in document["functions"]:
            helper.capture.exact_function_target(item)
        helper.capture.exact_kernel_control(document["evidence"])
    except Unknown:
        raise
    except (AssertionError, ValueError, KeyError, TypeError) as error:
        # The release oracle (check-capture-evidence.py) refuses by raising
        # AssertionError explicitly; that is a verdict, not a crash.
        raise Unknown(f"capture fails the release oracle's row contract: {error}") from error
    return document


def identity_relation(ref, owned):
    """'same', 'collision' (same dev/ino, other bytes) or 'other'."""
    if not isinstance(ref, dict) or owned is None:
        return "other"
    if list(ref.get("dev") or []) != owned["dev"] or ref.get("ino") != owned["ino"]:
        return "other"
    return "same" if ref.get("sha256") == owned["sha256"] else "collision"


def row_counts(rows):
    returned = sum(row["calls"] for row in rows)
    return {"rows": len(rows), "entered": returned + sum(row["in_flight"] for row in rows),
            "returned": returned}


def observe(document, owned, offset):
    """Measured outcome of one owned object in one capture (pure)."""
    rows = document["functions"]
    owned_rows = []
    collisions = 0
    for row in rows:
        relations = {identity_relation(row["target"]["object"], owned),
                     identity_relation(row["module"], owned)}
        if "collision" in relations:
            collisions += 1
        if "same" in relations:
            owned_rows.append(row)
    endpoint = [row for row in owned_rows
                if identity_relation(row["target"]["object"], owned) == "same"
                and offset is not None and row["target"]["file_offset"] == offset]
    others = [row for row in owned_rows if row not in endpoint]
    foreign = [row for row in rows if row not in owned_rows]
    return {
        "endpoint": row_counts(endpoint),
        "endpoint_names": sorted({name for row in endpoint for name in row["names"]}),
        "endpoint_ordinals": sorted({ordinal["ordinal"] for row in endpoint
                                     for ordinal in row["ordinals"]}),
        "endpoint_sole_owner": all(identity_relation(row["module"], owned) == "same"
                                   for row in endpoint),
        "other_owned": row_counts(others),
        "owned_rows": len(owned_rows),
        "identity_collisions": collisions,
        "foreign": row_counts(foreign),
        "declared": any(identity_relation(module, owned) == "same"
                        for module in document.get("capture", {}).get("modules", [])),
    }


def no_table_diagnostic_subjects(stderr_text):
    """Subjects of the observer's no-table diagnostics (labels, never identity)."""
    subjects = []
    for line in stderr_text.splitlines():
        if not line.startswith("p11scope: discovery") or NO_TABLE_DIAGNOSTIC not in line:
            continue
        match = re.search(r"discovery skipped (.+?) — ", line)
        if match is None:
            continue
        aggregated = re.match(r"^p11scope: discovery: [^:]+ ×[0-9]+: ", line) is not None
        subjects.append({"subject": match[1], "aggregated": aggregated})
    return subjects


def public_table_refusal(document):
    return any(skip == {"name": "discovery subject", "reason": TABLE_UNAVAILABLE}
               for skip in document["evidence"].get("skipped", []))


def judge_cell(name, expect, mode, *, ledger, observation, document, refusal, calls):
    """PASS or the list of reasons the cell stays UNKNOWN (pure)."""
    reasons = []
    if ledger is None:
        return ["fixture ledger is missing"]
    if ledger["entered"] != calls or ledger["returned"] != calls:
        reasons.append("fixture ledger is incomplete")
    if document is None or observation is None:
        return reasons + ["no attributable capture outcome"]
    if document["evidence"]["kernel_control"]["capture_halted"]:
        reasons.append("kernel capture halted")
    if observation["identity_collisions"]:
        reasons.append("a report row collides with the owned dev/ino under other bytes")
    endpoint = observation["endpoint"]
    if expect in ("supported", "foreign"):
        if endpoint["rows"] != 1:
            reasons.append(f"owned endpoint has {endpoint['rows']} report rows, wanted 1")
        if not observation["endpoint_sole_owner"]:
            reasons.append("owned endpoint row is not solely owned by the pinned module")
        if not observation["declared"]:
            reasons.append("capture.modules does not declare the pinned module")
        if SURFACE_ORDINAL[name] not in observation["endpoint_ordinals"]:
            reasons.append("owned endpoint row is not reached by the executed ordinal")
        if (endpoint["entered"], endpoint["returned"]) != (ledger["entered"], ledger["returned"]):
            reasons.append(f"owned count mismatch: ledger {ledger['entered']}/{ledger['returned']}"
                           f", capture {endpoint['entered']}/{endpoint['returned']}")
        if observation["other_owned"]["entered"]:
            reasons.append("unexpected owned rows counted calls")
        return reasons
    if observation["owned_rows"]:
        reasons.append(f"unsupported surface has {observation['owned_rows']} owned report rows")
    if document["evidence"]["completeness"] == "COMPLETE":
        reasons.append("capture claims COMPLETE while an executed surface stayed unobserved")
    if expect == "explicit-unsupported" and mode == "pid-hinted":
        if not refusal or not refusal.get("public"):
            reasons.append("no public no-table record")
        if not refusal or not refusal.get("bound"):
            reasons.append("no no-table diagnostic bound to the owned object")
    if expect == "bounded-unsupported" and mode == "pid-hinted":
        if observation["foreign"]["entered"]:
            reasons.append("a counted row in the JIT process cannot be attributed to "
                           "anonymous code")
    return reasons


SURFACE_ORDINAL = {name: spec["ordinal"] for name, spec in SURFACES.items()}
SURFACE_ORDINAL["foreign-traffic"] = FOREIGN["ordinal"]


# --------------------------------------------------------------------------
# H3: observer provenance, bound before launch.
# --------------------------------------------------------------------------

def run_git(arguments, root):
    result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True,
                            text=True, timeout=60, check=False)
    require(result.returncode == 0, f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout


def rustc_versions(observer_bytes):
    return sorted({match.decode("ascii") for match in
                   re.findall(rb"rustc version [0-9][ -~]{0,120}", observer_bytes)})


def make_provenance(observer, bpf_objects, *, root=ROOT, git=run_git):
    revision = git(["rev-parse", "HEAD"], root).strip()
    require(HEX40.fullmatch(revision), "source revision is not a commit id")
    status = git(["status", "--porcelain=v1", "--untracked-files=all"], root)
    require(status == "", "source checkout is dirty; provenance binds clean commits only")
    observer_bytes = Path(observer).read_bytes()
    objects = []
    for path in bpf_objects:
        data = Path(path).read_bytes()
        require(data, f"BPF object {path} is empty")
        offset = observer_bytes.find(data)
        require(offset >= 0, f"BPF object {path} is not embedded in the observer")
        require(observer_bytes.find(data, offset + 1) < 0,
                f"BPF object {path} is embedded more than once")
        objects.append({"name": Path(path).name, "sha256": sha256_bytes(data),
                        "size": len(data), "observer_offset": offset})
    names = sorted(item["name"] for item in objects)
    require(len(names) == len(set(names)), "duplicate BPF object names")
    return {
        "schema": PROVENANCE_SCHEMA,
        "source": {"revision": revision, "tree_clean": True,
                   "files": {rel: sha256_path(root / rel) for rel in BOUND_SOURCES}},
        "release_rust_version": (root / ".release-rust-version").read_text().strip(),
        "observer": {"sha256": sha256_bytes(observer_bytes), "size": len(observer_bytes),
                     "rustc": rustc_versions(observer_bytes)},
        "bpf_objects": objects,
    }


def validate_provenance(manifest, observer_bytes, *, root=ROOT, check_sources=True):
    """Refuse an unrelated or changed observer, dirty or unbound source, or a
    BPF artifact that is not the one embedded in this exact binary."""
    require(isinstance(manifest, dict) and manifest.get("schema") == PROVENANCE_SCHEMA,
            "provenance manifest schema is invalid")
    source = manifest.get("source")
    require(isinstance(source, dict) and HEX40.fullmatch(str(source.get("revision"))),
            "provenance is not bound to a source revision")
    require(source.get("tree_clean") is True, "provenance source checkout was dirty")
    files = source.get("files")
    require(isinstance(files, dict) and sorted(files) == sorted(BOUND_SOURCES)
            and all(HEX64.fullmatch(str(value)) for value in files.values()),
            "provenance does not bind every runner and fixture source")
    if check_sources:
        for rel in BOUND_SOURCES:
            require(sha256_path(root / rel) == files[rel],
                    f"{rel} changed since the provenance manifest was written")
    observer = manifest.get("observer")
    require(isinstance(observer, dict), "provenance names no observer")
    require(observer.get("sha256") == sha256_bytes(observer_bytes)
            and observer.get("size") == len(observer_bytes),
            "observer bytes are not the ones the provenance manifest binds")
    release = manifest.get("release_rust_version")
    require(isinstance(release, str) and release
            and any(f"rustc version {release} " in text for text in observer.get("rustc", [])),
            "observer was not built by the release compiler the manifest names")
    objects = manifest.get("bpf_objects")
    require(isinstance(objects, list) and objects, "provenance binds no BPF object")
    names = [item.get("name") for item in objects if isinstance(item, dict)]
    require(len(names) == len(objects) and len(set(names)) == len(names),
            "provenance BPF object list is malformed")
    for required in REQUIRED_BPF_OBJECTS:
        require(required in names, f"provenance does not bind BPF object {required}")
    for item in objects:
        offset, size = item.get("observer_offset"), item.get("size")
        require(type(offset) is int and type(size) is int and offset >= 0 and size > 0
                and offset + size <= len(observer_bytes),
                f"BPF object {item.get('name')} location is invalid")
        require(sha256_bytes(observer_bytes[offset:offset + size]) == item.get("sha256"),
                f"BPF object {item.get('name')} is not embedded in this observer")
    return {"revision": source["revision"], "observer_sha256": observer["sha256"]}


# --------------------------------------------------------------------------
# Fixtures.
# --------------------------------------------------------------------------

def fixture_commands(build):
    cc = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    fixtures = ROOT / "tests" / "fixtures"
    e16 = fixtures / "e16"
    shared = ["-fPIC", "-shared", "-Wl,-z,defs"]
    return [
        ("control.so", cc + shared + ["-DP11SCOPE_EXPORT_TABLES=1", "-o", str(build / "control.so"),
                                      str(fixtures / "live-discovery-provider.c")]),
        ("proxy.so", cc + shared + ["-o", str(build / "proxy.so"), str(e16 / "e16_hsm_proxy.c")]),
        ("direct.so", cc + shared + ["-o", str(build / "direct.so"),
                                     str(e16 / "e16_direct_exports.c")]),
        ("vendor.so", cc + shared + ["-o", str(build / "vendor.so"),
                                     str(e16 / "e16_vendor_only.c")]),
        ("driver", cc + ["-o", str(build / "driver"), str(e16 / "e16_driver.c"), "-ldl"]),
        ("jit-driver", cc + ["-o", str(build / "jit-driver"), str(e16 / "e16_jit_driver.c")]),
        ("static-provider.o", cc + ["-fPIC", "-c", "-o", str(build / "static-provider.o"),
                                    str(e16 / "e16_static_provider.c")]),
        ("static-driver", cc + ["-o", str(build / "static-driver"),
                                str(e16 / "e16_static_driver.c"),
                                str(build / "static-provider.o")]),
    ]


def dynamic_symbols(path):
    result = subprocess.run(["readelf", "--dyn-syms", "-W", str(path)], capture_output=True,
                            text=True, timeout=60, check=False)
    require(result.returncode == 0, f"readelf failed on {path}")
    names = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 8:
            names.add(fields[7].split("@")[0])
    return names


def build_fixtures(build):
    """Compile every fixture, prove the dynamic-export shapes, copy foreign."""
    records = []
    for output, command in fixture_commands(build):
        result = subprocess.run(command, capture_output=True, text=True, timeout=300,
                                check=False)
        require(result.returncode == 0, f"fixture build {output} failed: {result.stderr}")
        records.append({"output": output, "command": command,
                        "sha256": sha256_path(build / output)})
    factories = {"C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface",
                 "NSC_GetFunctionList", "FC_GetFunctionList"}
    require(not factories & dynamic_symbols(build / "static-driver"),
            "static driver must not export a registry factory")
    require(not factories & dynamic_symbols(build / "direct.so")
            and "C_GenerateRandom" in dynamic_symbols(build / "direct.so"),
            "direct-export fixture shape is wrong")
    vendor = dynamic_symbols(build / "vendor.so")
    require(not factories & vendor and "Vendor_GetFunctionList" in vendor,
            "vendor-only fixture shape is wrong")
    # Byte-identical, physically distinct: the foreign trap for identity.
    shutil.copyfile(build / "control.so", build / "foreign.so")
    records.append({"output": "foreign.so", "command": ["copy", "control.so"],
                    "sha256": sha256_path(build / "foreign.so")})
    return records


def driver_argv(spec, build, calls, foreign_calls):
    argv = []
    for index, word in enumerate(spec["argv"]):
        if word == "@calls":
            argv.append(str(calls))
        elif word == "@foreign_calls":
            argv.append(str(foreign_calls))
        elif word.startswith("@"):
            argv.append(str(build / word[1:]))
        elif index == 0:
            argv.append(str(build / word))
        else:
            argv.append(word)
    return argv


# --------------------------------------------------------------------------
# Owned processes.
# --------------------------------------------------------------------------

def outcome_of(returncode):
    if returncode is None:
        return {"exit_code": None, "signal": None}
    if returncode < 0:
        return {"exit_code": None, "signal": -returncode}
    return {"exit_code": returncode, "signal": None}


def pidfd_terminal(pidfd):
    return bool(select.select([pidfd], [], [], 0)[0])


def wait_pidfd(pidfd, deadline):
    while not pidfd_terminal(pidfd):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        select.select([pidfd], [], [], min(remaining, 0.5))
    return True


def settle(helper, process, pidfd, proc_root, *, first_signal=signal.SIGTERM):
    """Bounded owned cleanup through the shared pidfd custody seam."""
    record = {"attempted": False, "error": None}
    if pidfd is not None and not pidfd_terminal(pidfd):
        record["attempted"] = True
        try:
            starttime = helper.receipt.read_birth(proc_root, process.pid)
            handles = helper.receipt.acquire_process_tree(proc_root, process.pid, starttime)
            try:
                record["teardown"] = helper.receipt.teardown_custody(handles, first_signal, 5, 5)
            finally:
                for owned in handles:
                    os.close(owned["pidfd"])
        except (OSError, ValueError) as error:
            record["error"] = str(error)
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except OSError:
                pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        record["error"] = (record["error"] or "") + "; owned process was not reaped"
    return record


class Participant:
    def __init__(self, name, spec, argv, private, build):
        self.name = name
        self.spec = spec
        self.argv = argv
        self.dir = private.subdir(name)
        self.build = build
        self.process = None
        self.pidfd = None
        self.reader = None
        self.ready = None
        self.receipts = {}
        self.cleanup = None
        self.timed_out = False

    def launch(self):
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "P11SCOPE_E16_HOLD": "1",
               "P11SCOPE_FIXTURE_QUIET": "1"}
        self.process = subprocess.Popen(self.argv, cwd=self.build, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                        start_new_session=True, close_fds=True)
        self.pidfd = os.pidfd_open(self.process.pid)
        self.reader = FramedReader(self.process.stderr.fileno())

    def send(self, byte):
        try:
            self.process.stdin.write(byte)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise Unknown(f"{self.name}: gate byte not delivered: {error}") from error

    def protocol_line(self, deadline):
        return next_protocol_line(self.reader, deadline)


class Observer:
    def __init__(self, argv, private):
        self.argv = argv
        self.private = private
        self.process = None
        self.pidfd = None
        self.timed_out = False
        self.cleanup = None
        self.ready_line = None

    def launch(self):
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        if "SUDO_UID" in os.environ:
            env["SUDO_UID"] = os.environ["SUDO_UID"]
        stdout = self.private.create("observer.stdout")
        stderr = self.private.create("observer.stderr")
        try:
            self.process = subprocess.Popen(self.argv, env=env, stdin=subprocess.DEVNULL,
                                            stdout=stdout, stderr=stderr,
                                            start_new_session=True, close_fds=True)
        finally:
            os.close(stdout)
            os.close(stderr)
        self.pidfd = os.pidfd_open(self.process.pid)

    def stderr_text(self):
        fd = os.open("observer.stderr", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.private.fd)
        try:
            data = os.read(fd, MAX_OBSERVER_LOG + 1)
        finally:
            os.close(fd)
        require(len(data) <= MAX_OBSERVER_LOG, "observer stderr exceeds its bound")
        return data.decode("utf-8", "replace")


def ready_and_live(read_stderr, pidfd):
    """H5: a readiness line counts only while its exact observer still runs."""
    ready = [line for line in read_stderr().splitlines() if READY_LINE.fullmatch(line)]
    if not ready:
        return None
    require(len(ready) == 1, "observer announced readiness more than once")
    require(not pidfd_terminal(pidfd),
            "readiness marker came from an observer that already exited; GO withheld")
    return ready[0]


def wait_observer_ready(observer, deadline, poll=0.05):
    while True:
        line = ready_and_live(observer.stderr_text, observer.pidfd)
        if line is not None:
            return line
        require(not pidfd_terminal(observer.pidfd), "observer exited before readiness")
        require(time.monotonic() < deadline, "observer readiness deadline expired")
        time.sleep(poll)


def now_ns():
    return time.monotonic_ns()


def run_group(helper, private, build, members, observer_argv, *, proc_root, duration,
              ready_timeout, observer_grace, frozen_observer=None, frozen_sha256=None):
    """Execute one owned run end to end; never raises past cleanup.

    Order (H5): drivers ready -> pre-GO receipts (H2) -> observer launched ->
    observer ready while live -> GO -> every ledger closed -> observer exit
    -> retained-workload checks -> release -> drivers reaped.
    """
    timeline = {}
    error = None
    observer = Observer(None, private)
    participants = []
    try:
        for name, spec, argv in members:
            participants.append(Participant(name, spec, argv, private, build))
        for participant in participants:
            participant.launch()
        for participant in participants:
            line = participant.protocol_line(time.monotonic() + ready_timeout)
            participant.ready = parse_ready(line)
            require(participant.ready["pid"] == participant.process.pid,
                    f"{participant.name}: ready line names another PID")
        timeline["drivers_ready"] = now_ns()
        for participant in participants:
            take_receipts(helper, participant, proc_root)
        timeline["receipts_pinned"] = now_ns()
        if frozen_observer is not None:
            require(sha256_path(frozen_observer) == frozen_sha256,
                    "frozen observer changed before launch")
        observer.argv = observer_argv(participants)
        observer.launch()
        timeline["observer_spawned"] = now_ns()
        observer.ready_line = wait_observer_ready(observer, time.monotonic() + ready_timeout)
        timeline["observer_ready_live"] = now_ns()
        for participant in participants:
            participant.send(b"G")
        timeline["go_sent"] = now_ns()
        ledger_deadline = time.monotonic() + max(5.0, duration / 2)
        for participant in participants:
            for _ in range(participant.ready["calls"] + 1):
                participant.protocol_line(ledger_deadline)
        timeline["ledgers_closed"] = now_ns()
        observer_deadline = time.monotonic() + duration + observer_grace
        if not wait_pidfd(observer.pidfd, observer_deadline):
            observer.timed_out = True
            raise Unknown("observer did not finish within its deadline")
        observer.process.wait(timeout=10)
        timeline["observer_exited"] = now_ns()
        for participant in participants:
            require(not pidfd_terminal(participant.pidfd),
                    f"{participant.name}: workload exited before release")
            for receipt in participant.receipts.values():
                if receipt.get("schema") == helper.receipt.MAPPING_SCHEMA:
                    receipt_still_holds(helper.receipt, proc_root, receipt)
                    path_still_names_pin(helper.receipt, receipt["expected"]["path"], receipt)
                else:
                    still = anonymous_mapping_receipt(helper.receipt, proc_root,
                                                      participant.ready,
                                                      int(receipt["endpoint_address"], 16))
                    require(still["mapping"] == receipt["mapping"],
                            "anonymous endpoint mapping changed before release")
        timeline["retained_checks"] = now_ns()
        for participant in participants:
            participant.send(b"X")
        timeline["release_sent"] = now_ns()
        release_deadline = time.monotonic() + 10
        for participant in participants:
            if not wait_pidfd(participant.pidfd, release_deadline):
                participant.timed_out = True
                raise Unknown(f"{participant.name}: did not exit after release")
            participant.process.wait(timeout=10)
        timeline["drivers_exited"] = now_ns()
    except (Unknown, OSError, subprocess.SubprocessError) as caught:
        error = f"{type(caught).__name__}: {caught}"
    finally:
        if observer.process is not None:
            observer.cleanup = settle(helper, observer.process, observer.pidfd, proc_root,
                                      first_signal=signal.SIGINT)
        for participant in participants:
            if participant.process is None:
                continue
            participant.cleanup = settle(helper, participant.process, participant.pidfd,
                                         proc_root)
            participant.reader.drain(time.monotonic() + 2)
            for stream in (participant.process.stdin, participant.process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
            os.close(participant.pidfd)
            participant.dir.write_bytes("driver.stderr", bytes(participant.reader.transcript))
            for kind, receipt in participant.receipts.items():
                participant.dir.write_json(f"receipt-{kind}.json", receipt)
            participant.dir.close()
        if observer.pidfd is not None:
            os.close(observer.pidfd)
    return {
        "error": error,
        "timeline": timeline,
        "observer": {"argv": observer.argv,
                     **outcome_of(None if observer.process is None
                                  else observer.process.returncode),
                     "launched": observer.process is not None,
                     "timed_out": observer.timed_out, "cleanup": observer.cleanup,
                     "ready_line": observer.ready_line},
        "participants": [{"name": participant.name, "argv": participant.argv,
                          "ready": participant.ready,
                          **outcome_of(None if participant.process is None
                                       else participant.process.returncode),
                          "launched": participant.process is not None,
                          "timed_out": participant.timed_out,
                          "cleanup": participant.cleanup,
                          "receipts": sorted(participant.receipts),
                          "hint": str(build / participant.spec["hint"])}
                         for participant in participants],
    }


def take_receipts(helper, participant, proc_root):
    """H2: pin every identity the cell will be judged by, before GO."""
    ready = participant.ready
    spec = participant.spec

    def pinned(kind, address):
        name = f"handshake-{kind}"
        participant.dir.write_bytes(name, handshake_text(ready, address).encode())
        return file_mapping_receipt(helper.receipt, proc_root, ready, address,
                                    participant.build / spec["hint"],
                                    participant.dir.child_path(name))

    if spec["endpoint"] == "anonymous":
        participant.receipts["endpoint"] = anonymous_mapping_receipt(
            helper.receipt, proc_root, ready, ready["endpoint"])
        participant.receipts["image"] = pinned("image", ready["image"])
    else:
        participant.receipts["endpoint"] = pinned("endpoint", ready["endpoint"])


# --------------------------------------------------------------------------
# Reduce a run from its retained artifacts; the same code serves verify.
# --------------------------------------------------------------------------

def read_artifact(directory, rel, limit):
    fd = os.open(rel, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), f"{rel} is not a regular file")
        require(info.st_size <= limit, f"{rel} exceeds its {limit}-byte bound")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def reduce_run(helper, campaign, run, files, calls, foreign_calls):
    """Cell results of one run, from retained bytes only (pure)."""
    mode = CAMPAIGNS[campaign]["mode"]
    document, capture_error = None, None
    try:
        document = load_capture(helper, files.get(f"{run['id']}/capture.json", b""))
    except Unknown as error:
        capture_error = str(error)
    stderr_text = files.get(f"{run['id']}/observer.stderr", b"").decode("utf-8", "replace")
    results = []
    for participant in run["participants"]:
        name = participant["name"]
        spec = FOREIGN if name == "foreign-traffic" else SURFACES[name]
        wanted = foreign_calls if name == "foreign-traffic" else calls
        result = {"name": name, "expect": spec["expect"], "mode": mode, "run": run["id"]}
        reasons = []
        try:
            ledger = parse_ledger(files.get(f"{run['id']}/{name}/driver.stderr", b""),
                                  label=spec["label"], calls=wanted)
        except Unknown as error:
            ledger = None
            reasons.append(f"ledger: {error}")
        receipts = {}
        for kind in participant["receipts"]:
            raw = files.get(f"{run['id']}/{name}/receipt-{kind}.json")
            receipts[kind] = json.loads(raw) if raw else None
        owned, offset, observation, refusal = None, None, None, None
        try:
            if spec["endpoint"] == "file":
                receipt = receipts.get("endpoint")
                require(receipt is not None, "pre-GO endpoint receipt is missing")
                owned = owned_identity(helper, receipt)
                offset = endpoint_file_offset(receipt)
            else:
                anonymous = receipts.get("endpoint")
                require(anonymous is not None and anonymous.get("schema") == ANONYMOUS_SCHEMA,
                        "pre-GO anonymous endpoint receipt is missing")
                image = receipts.get("image")
                require(image is not None, "pre-GO image receipt is missing")
                owned = owned_identity(helper, image)
            if ledger is not None:
                require(ledger["ready"]["pid"] == participant["ready"]["pid"]
                        and ledger["ready"]["endpoint"] == participant["ready"]["endpoint"],
                        "ledger ready line disagrees with the recorded participant")
                for receipt in receipts.values():
                    require(receipt["pid"] == ledger["ready"]["pid"]
                            and receipt["starttime"] == ledger["ready"]["starttime"],
                            "receipt names another process birth")
            if document is not None:
                observation = observe(document, owned, offset)
                if spec["expect"] == "explicit-unsupported":
                    subjects = no_table_diagnostic_subjects(stderr_text)
                    # Bound: the only no-table diagnostic names the owned
                    # object's label, unaggregated; the label names the pinned
                    # object because the run re-proved path identity before
                    # release (path_still_names_pin).
                    refusal = {"public": public_table_refusal(document),
                               "diagnostics": subjects,
                               "bound": len(subjects) == 1
                               and subjects[0]["subject"] == participant["hint"]
                               and not subjects[0]["aggregated"]}
                elif spec["expect"] == "bounded-unsupported":
                    subjects = no_table_diagnostic_subjects(stderr_text)
                    refusal = {"boundary": JIT_BOUNDARY,
                               "image_no_table_record": any(
                                   item["subject"] == participant["hint"] for item in subjects)}
        except Unknown as error:
            reasons.append(str(error))
        if capture_error is not None:
            reasons.append(f"capture: {capture_error}")
        reasons += judge_cell(name, spec["expect"], mode, ledger=ledger,
                              observation=observation, document=document,
                              refusal=refusal, calls=wanted)
        result.update(owned_identity=owned, endpoint_file_offset=offset,
                      ledger=None if ledger is None else
                      {"entered": ledger["entered"], "returned": ledger["returned"]},
                      observation=observation, refusal=refusal,
                      completeness=None if document is None else document["evidence"]["completeness"],
                      verdict="PASS" if not reasons else "UNKNOWN", reasons=reasons)
        results.append(result)
    return results


def process_failures(label, outcome):
    failures = []
    if not outcome.get("launched"):
        failures.append(f"{label} was never launched")
    if outcome.get("signal") is not None:
        failures.append(f"{label} ended by signal {outcome['signal']}")
    elif outcome.get("exit_code") != 0:
        failures.append(f"{label} exit code {outcome.get('exit_code')!r}")
    if outcome.get("timed_out") is not False:
        failures.append(f"{label} timed out")
    cleanup = outcome.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("error") is not None:
        failures.append(f"{label} cleanup failed: {cleanup}")
    elif cleanup.get("attempted"):
        failures.append(f"{label} needed forced cleanup")
    return failures


TIMELINE = ("drivers_ready", "receipts_pinned", "observer_spawned", "observer_ready_live",
            "go_sent", "ledgers_closed", "observer_exited", "retained_checks", "release_sent",
            "drivers_exited")


def required_cells(campaign):
    return [(name, SURFACES[name]["expect"], CAMPAIGNS[campaign]["mode"]) for name in CELL_ORDER]


def required_runs(campaign):
    if CAMPAIGNS[campaign]["foreign"]:
        return [["system", list(CELL_ORDER) + ["foreign-traffic"]]]
    return [[name, [name]] for name in CELL_ORDER]


def verify_record(helper, record, files, *, frozen_observer_bytes, manifest):
    """The single acceptance function, for `run` and `verify` alike."""
    failures = []
    require(isinstance(record, dict) and record.get("schema") == SCHEMA,
            "record schema is not E16 v2")
    campaign = record.get("campaign")
    require(campaign in CAMPAIGNS, f"unknown campaign {campaign!r}")
    calls, foreign_calls = record.get("calls"), record.get("foreign_calls")
    require(type(calls) is int and type(foreign_calls) is int and 0 < calls < foreign_calls,
            "call counts are invalid (foreign must differ from owned)")
    validate_provenance(manifest, frozen_observer_bytes, check_sources=False)
    require(record.get("provenance") == manifest, "record provenance is not the frozen manifest")
    # Exact campaign manifest: nothing omitted, duplicated or relabeled.
    runs = record.get("runs")
    require(isinstance(runs, list), "record has no runs")
    require([[run.get("id"), [p.get("name") for p in run.get("participants", [])]]
             for run in runs] == required_runs(campaign),
            "runs do not match the exact campaign manifest")
    cells = record.get("cells")
    require(isinstance(cells, list)
            and [(cell.get("name"), cell.get("expect"), cell.get("mode"))
                 for cell in cells if cell.get("name") != "foreign-traffic"]
            == required_cells(campaign),
            "cells do not match the exact campaign manifest (omitted, duplicate or relabeled)")
    listed = record.get("files")
    require(isinstance(listed, dict), "record lists no artifact digests")
    for rel, digest in listed.items():
        require(rel in files and sha256_bytes(files[rel]) == digest,
                f"artifact {rel} is missing or changed")
    derived = []
    for run in runs:
        derived += reduce_run(helper, campaign, run, files, calls, foreign_calls)
        if run.get("error"):
            failures.append(f"run {run['id']}: {run['error']}")
        failures += process_failures(f"run {run['id']} observer", run["observer"])
        for participant in run["participants"]:
            failures += process_failures(f"run {run['id']} {participant['name']}", participant)
        stamps = [run["timeline"].get(key) for key in TIMELINE]
        if not all(type(stamp) is int for stamp in stamps) or stamps != sorted(stamps) \
                or len(set(stamps)) != len(stamps):
            failures.append(f"run {run['id']}: lifecycle order is incomplete or violated")
    require(derived == cells, "recorded cells disagree with cells re-derived from artifacts")
    for cell in cells:
        if cell["verdict"] != "PASS":
            failures.append(f"cell {cell['name']}: " + "; ".join(cell["reasons"]))
    if failures:
        raise Unknown("; ".join(failures))
    return {"status": "PASS", "campaign": campaign,
            "cells": {cell["name"]: cell["verdict"] for cell in cells}}


# --------------------------------------------------------------------------
# Commands.
# --------------------------------------------------------------------------

def command_provenance(args):
    require(os.geteuid() != 0, "write provenance as the unprivileged checkout owner")
    manifest = make_provenance(args.observer, args.bpf_object)
    out = Path(args.out)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"provenance": str(out), "revision": manifest["source"]["revision"],
                      "observer_sha256": manifest["observer"]["sha256"]}, sort_keys=True))


def product_observer_argv(frozen, build, duration):
    """The real observer command lines: hinted `--pid`, or unhinted `--system`."""
    def argv_for(campaign, participants, capture):
        argv = [str(frozen), "profile"]
        if CAMPAIGNS[campaign]["foreign"]:
            argv += ["--system"]
        else:
            (participant,) = participants
            argv += ["--pid", str(participant.process.pid), "--module",
                     str(build / participant.spec["hint"])]
        return argv + ["--duration", str(duration), "-o", str(capture)]
    return argv_for


def execute_campaign(helper, private, campaign, *, build, fixture_records, observer_argv_for,
                     calls, foreign_calls, duration, ready_timeout, observer_grace, manifest,
                     frozen, proc_root="/proc"):
    """Run every required run of one campaign and write the record.

    ``frozen`` is the private observer copy the manifest binds; it is
    re-hashed before every launch and after the last run.
    """
    frozen_sha256 = sha256_path(frozen)
    runs = []
    for run_id, names in required_runs(campaign):
        run_dir = private.subdir(run_id)
        members = []
        for name in names:
            spec = FOREIGN if name == "foreign-traffic" else SURFACES[name]
            members.append((name, spec, driver_argv(spec, build, calls, foreign_calls)))
        capture = run_dir.path / "capture.json"
        run = run_group(helper, run_dir, build, members,
                        lambda participants, capture=capture: observer_argv_for(
                            campaign, participants, capture),
                        proc_root=proc_root, duration=duration, ready_timeout=ready_timeout,
                        observer_grace=observer_grace, frozen_observer=frozen,
                        frozen_sha256=frozen_sha256)
        run["id"] = run_id
        run_dir.close()
        runs.append(run)
    require(sha256_path(frozen) == frozen_sha256, "frozen observer changed during the campaign")
    files = collect_files(private.path, runs)
    cells = []
    for run in runs:
        cells += reduce_run(helper, campaign, run, files, calls, foreign_calls)
    record = {"schema": SCHEMA, "campaign": campaign, "calls": calls,
              "foreign_calls": foreign_calls, "provenance": manifest,
              "host": {"kernel": os.uname().release, "machine": os.uname().machine},
              "fixtures": fixture_records, "runs": runs, "cells": cells,
              "files": {rel: sha256_bytes(data) for rel, data in sorted(files.items())}}
    private.write_json("e16-record.json", record)
    return record, files


def freeze_observer(private, observer_bytes):
    frozen_dir = private.subdir("observer")
    try:
        frozen_dir.write_bytes("p11scope", observer_bytes, mode=0o500)
    finally:
        frozen_dir.close()
    return frozen_dir.path / "p11scope"


def command_run(args):
    if os.geteuid() != 0:
        raise Unknown("run needs root; use: " + " ".join(OPERATOR_COMMAND) + " ...")
    require(0 < args.calls < args.foreign_calls <= 100000, "call counts are invalid")
    manifest = json.loads(Path(args.provenance).read_text(encoding="utf-8"))
    observer_bytes = Path(args.observer).read_bytes()
    # Bind observer, BPF objects and every runner/fixture source before
    # anything is loaded, created or launched.
    validate_provenance(manifest, observer_bytes)
    helper = helpers()
    private = create_private_root(args.artifacts)
    try:
        frozen = freeze_observer(private, observer_bytes)
        validate_provenance(manifest, frozen.read_bytes())
        build_dir = private.subdir("build")
        build = build_dir.path
        build_dir.close()
        fixture_records = build_fixtures(build)
        record, files = execute_campaign(
            helper, private, args.campaign, build=build, fixture_records=fixture_records,
            observer_argv_for=product_observer_argv(frozen, build, args.duration),
            calls=args.calls, foreign_calls=args.foreign_calls, duration=args.duration,
            ready_timeout=args.ready_timeout, observer_grace=args.observer_grace,
            manifest=manifest, frozen=frozen)
        try:
            summary = verify_record(helper, record, files,
                                    frozen_observer_bytes=frozen.read_bytes(), manifest=manifest)
        except Unknown as error:
            private.write_json("e16-verdict.json", {"status": "UNKNOWN", "reason": str(error)})
            raise
        private.write_json("e16-verdict.json", summary)
        print(json.dumps({**summary, "record": str(private.path / "e16-record.json")},
                         sort_keys=True))
    finally:
        private.close()


def collect_files(root, runs):
    """Every retained artifact the reducers read, keyed by relative path."""
    files = {}
    directory = os.open(root, DIRECTORY_FLAGS)
    try:
        for run in runs:
            names = [f"{run['id']}/capture.json", f"{run['id']}/observer.stderr",
                     f"{run['id']}/observer.stdout"]
            for participant in run["participants"]:
                names.append(f"{run['id']}/{participant['name']}/driver.stderr")
                names += [f"{run['id']}/{participant['name']}/receipt-{kind}.json"
                          for kind in participant["receipts"]]
            for rel in names:
                try:
                    files[rel] = read_artifact(directory, rel, MAX_CAPTURE)
                except FileNotFoundError:
                    continue
    finally:
        os.close(directory)
    return files


def command_verify(args):
    directory = os.open(args.artifacts, DIRECTORY_FLAGS)
    try:
        record = json.loads(read_artifact(directory, "e16-record.json", MAX_CAPTURE))
        frozen = read_artifact(directory, "observer/p11scope", 1 << 31)
    finally:
        os.close(directory)
    files = collect_files(args.artifacts, record.get("runs", []))
    summary = verify_record(helpers(), record, files, frozen_observer_bytes=frozen,
                            manifest=record.get("provenance"))
    print(json.dumps(summary, sort_keys=True))


# --------------------------------------------------------------------------
# Self-test: reducers in-process, real fixtures under the hold protocol.
# --------------------------------------------------------------------------

def mirror_proc(pid, destination):
    """A /proc subset for one live child: real stat/maps/mountinfo, and
    map_files links an unprivileged reader can follow."""
    process = Path(destination) / str(pid)
    (process / "map_files").mkdir(parents=True)
    (process / "ns").mkdir()
    (process / "ns" / "mnt").write_text("mirrored namespace\n", encoding="utf-8")
    for name in ("stat", "maps", "mountinfo"):
        (process / name).write_bytes(Path(f"/proc/{pid}/{name}").read_bytes())
    for line in (process / "maps").read_text(encoding="utf-8").splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[4] != "0" and fields[5].startswith("/"):
            link = process / "map_files" / fields[0]
            if not link.exists():
                link.symlink_to(fields[5])


def synthetic_capture(rows, *, completeness="PARTIAL", skipped=(), modules=()):
    return {"schema": PROFILE_SCHEMA, "functions": rows,
            "capture": {"modules": list(modules)},
            "evidence": {"completeness": completeness, "skipped": list(skipped),
                         "kernel_control": {"capture_halted": False}}}


def synthetic_row(identity, offset, calls, *, in_flight=0, ordinal=0, module=None):
    return {"names": ["unknown"], "calls": calls, "in_flight": in_flight,
            "target": {"object": identity, "file_offset": offset},
            "ordinals": [] if ordinal is None else [{"table_file_offset": 0, "ordinal": ordinal}],
            "module": identity if module is None else module,
            "module_ambiguous": False, "module_unresolved": False}


def self_test_model():
    owned = {"dev": [0, 35], "ino": 42, "sha256": "a" * 64}
    foreign = {"dev": [0, 35], "ino": 43, "sha256": "a" * 64}
    ledger = {"entered": 4, "returned": 4}

    def judge(document, expect="supported", refusal=None, name="control"):
        observation = observe(document, owned, 0x1000)
        return judge_cell(name, expect, "pid-hinted", ledger=ledger, observation=observation,
                          document=document, refusal=refusal, calls=4)

    good = synthetic_capture([synthetic_row(owned, 0x1000, 4), synthetic_row(foreign, 0x1000, 9)],
                             modules=[owned, foreign])
    assert judge(good) == [], judge(good)
    # Foreign byte-identical traffic is never owned authority.
    swapped = synthetic_capture([synthetic_row(owned, 0x1000, 0), synthetic_row(foreign, 0x1000, 4)],
                                modules=[owned, foreign])
    assert any("owned count mismatch" in reason for reason in judge(swapped))
    # Unknown names with exact identity/offset pass; a wrong offset does not.
    shifted = synthetic_capture([synthetic_row(owned, 0x1010, 4)], modules=[owned])
    assert any("1" in reason and "rows" in reason for reason in judge(shifted))
    # Unsupported: owned rows are unexpected; a foreign-only refusal is not bound.
    refused = synthetic_capture([], skipped=[{"name": "discovery subject",
                                              "reason": TABLE_UNAVAILABLE}])
    assert judge(refused, "explicit-unsupported", {"public": True, "bound": True}) == []
    assert judge(refused, "explicit-unsupported", {"public": True, "bound": False})
    admitted = synthetic_capture([synthetic_row(owned, 0x1000, 0)], modules=[owned])
    assert judge(admitted, "explicit-unsupported", {"public": True, "bound": True})
    # Collapsed signal outcomes stay failures.
    assert process_failures("observer", {"launched": True, "exit_code": None, "signal": 15,
                                         "timed_out": False, "cleanup": {"attempted": False,
                                                                         "error": None}})
    print("  model: identity/offset reduction, foreign and refusal binding ok")


def self_test_fixtures(helper):
    with tempfile.TemporaryDirectory(prefix="e16-selftest-") as raw:
        base = Path(raw)
        build = base / "build"
        build.mkdir()
        build_fixtures(build)
        for name in CELL_ORDER:
            spec = SURFACES[name]
            argv = driver_argv(spec, build, 3, 5)
            env = {"PATH": "/usr/bin:/bin", "P11SCOPE_E16_HOLD": "1", "P11SCOPE_FIXTURE_QUIET": "1"}
            process = subprocess.Popen(argv, cwd=build, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                       start_new_session=True)
            try:
                reader = FramedReader(process.stderr.fileno())
                deadline = time.monotonic() + 20
                ready = parse_ready(next_protocol_line(reader, deadline))
                assert ready["pid"] == process.pid
                mirror = base / f"proc-{name}"
                mirror_proc(process.pid, mirror)
                address = ready["image" if spec["endpoint"] == "anonymous" else "endpoint"]
                handshake = base / f"{name}.handshake"
                handshake.write_text(handshake_text(ready, address), encoding="utf-8")
                receipt = file_mapping_receipt(helper.receipt, mirror, ready, address,
                                               build / spec["hint"], handshake)
                if spec["endpoint"] == "anonymous":
                    anonymous_mapping_receipt(helper.receipt, mirror, ready, ready["endpoint"])
                else:
                    endpoint_file_offset(receipt)
                owned_identity(helper, receipt)
                process.stdin.write(b"G")
                process.stdin.flush()
                while not reader.buffer.endswith(b"done calls=3\n"):
                    reader._fill(deadline)
                process.stdin.write(b"X")
                process.stdin.close()
                assert process.wait(timeout=20) == 0
                reader.drain(time.monotonic() + 5)
                parse_ledger(bytes(reader.transcript), label=spec["label"], calls=3)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stderr.close()
        print("  fixtures: six drivers, hold protocol, pre-GO receipts and ledgers ok")


def self_test():
    print("qualify-e16-surfaces self-test")
    self_test_model()
    self_test_fixtures(helpers())
    print("qualify-e16-surfaces self-test: PASS")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--self-test", action="store_true")
    commands = parser.add_subparsers(dest="command")
    provenance = commands.add_parser("provenance")
    provenance.add_argument("--observer", required=True)
    provenance.add_argument("--bpf-object", required=True, action="append")
    provenance.add_argument("--out", required=True)
    run = commands.add_parser("run")
    run.add_argument("--campaign", required=True, choices=sorted(CAMPAIGNS))
    run.add_argument("--observer", required=True)
    run.add_argument("--provenance", required=True)
    run.add_argument("--artifacts", required=True)
    run.add_argument("--calls", type=int, default=16)
    run.add_argument("--foreign-calls", type=int, default=23)
    run.add_argument("--duration", type=int, default=8)
    run.add_argument("--ready-timeout", type=float, default=180.0)
    run.add_argument("--observer-grace", type=float, default=120.0)
    verify = commands.add_parser("verify")
    verify.add_argument("--artifacts", required=True)
    args = parser.parse_args(argv)
    if not args.self_test and args.command is None:
        parser.error("a command or --self-test is required")
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.self_test:
            self_test()
        elif args.command == "provenance":
            command_provenance(args)
        elif args.command == "run":
            command_run(args)
        else:
            command_verify(args)
    except (Unknown, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"E16 UNKNOWN: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
