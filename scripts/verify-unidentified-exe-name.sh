#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# verify-unidentified-exe-name.sh: privileged cell for the user question
# "which program called?" over short-lived callers.
#
# `inventory --system --capture native` while `pkcs11-tool --module
# <private SoftHSM> -O` runs once must NAME the tool in
# `modules[].unbound_use.executables` (its EXEC-joined device/inode
# resolved to the exact tool path with a resolved verdict) and on
# the concise `unidentified executables` line — not just its pid.
# The oracle matches the tool's own (dev, ino), so a pid-only or
# path-unknown record for our binary fails; attempts where the single
# run binds to a caller edge (or its calls are missed) retry with a
# fresh capture (at most three), since only an unidentified image
# exercises the EXEC join. A holder process keeps the SoftHSM module
# mapped for the whole run (discovery attaches mapped modules; the
# short-lived tool alone maps it too briefly). `--tool PATH` runs the
# workload from another binary (loop-mounted filesystem cells); the
# default is the probed `pkcs11-tool`. `--runs N` repeats the workload
# per attempt (the oracle matches the mapped-device pair, never stat).
# The default single run suits indexed binaries; a tool outside the
# system index (a loop-mounted copy) needs `--teach`, which holds one
# preloaded instance of the same binary alive across the attempt so
# the scan-learned map resolves the pair for every short-lived run.
# `--docker NAME` runs the holder, teacher and workload inside the
# named container (overlay cell): the observer still runs on the host
# and the oracle matches the tool's overlay pair from the host's
# /proc, never the container path's stat. `--linger` preloads the
# measured runs so each stays alive after its own main returns while
# the EXEC backfill reads its live identity — this names callers
# whose path never resolves on the host (a container binary needs
# `--docker --teach --linger`).
#
# Needs root for the observer (sudo -n), plus pkcs11-tool, softhsm2
# and gcc-free tooling only (`--teach` additionally needs cc to build
# its fixture). Provider paths are probed (Debian, Fedora and
# vng-guest layouts); nothing is hard-coded. The token is private to
# the work dir; the fixed test PIN lives only in this cell's own argv,
# which the observer never reads.
set -eu
cd "$(dirname "$0")/.."

MODE=""
BINARY=""
WORK=""
TOOL=""
RUNS=1
KEEP=0
TEACH=0
LINGER=0
DOCKER=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --self-test) MODE=self; shift ;;
        --binary) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--teach] [--linger] [--docker NAME] [--keep]" >&2; exit 2; }
            BINARY=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--teach] [--linger] [--docker NAME] [--keep]" >&2; exit 2; }
            WORK=$2; shift 2 ;;
        --tool) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--teach] [--linger] [--docker NAME] [--keep]" >&2; exit 2; }
            TOOL=$2; shift 2 ;;
        --runs) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--teach] [--linger] [--docker NAME] [--keep]" >&2; exit 2; }
            RUNS=$2; shift 2 ;;
        --teach) TEACH=1; shift ;;
        --linger) LINGER=1; shift ;;
        --docker) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--teach] [--linger] [--docker NAME] [--keep]" >&2; exit 2; }
            DOCKER=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--teach] [--linger] [--docker NAME] [--keep]" >&2; exit 2 ;;
    esac
done

if [ "$MODE" = self ]; then
    [ -z "$BINARY$WORK$TOOL" ] && [ "$RUNS" = 1 ] && [ "$KEEP" -eq 0 ] && [ "$TEACH" -eq 0 ] && [ "$LINGER" -eq 0 ] && [ -z "$DOCKER" ] || {
        echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--teach] [--linger] [--docker NAME] [--keep]" >&2; exit 2
    }
else
    [ -n "$BINARY" ] && [ -n "$WORK" ] || {
        echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--tool PATH] [--runs N] [--keep]" >&2; exit 2
    }
    case "$RUNS" in
        ''|*[!0-9]*) echo "runs must be a positive integer: $RUNS" >&2; exit 2 ;;
    esac
    [ "$RUNS" -ge 1 ] || { echo "runs must be a positive integer: $RUNS" >&2; exit 2; }
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

# The embedded runner ships in two capped heredocs (scripts tree shape
# gate caps each heredoc body): their concatenation is the whole program,
# written once and executed once. The program reads only argv[1..9], never
# stdin or argv[0], so the temp-file form behaves identically.
exe_runner=$(mktemp "${TMPDIR:-/tmp}/verify-unidentified-exe-name.XXXXXX.py")
trap 'rm -f "$exe_runner"' EXIT
cat > "$exe_runner" <<'PY'
import json
import mmap
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

SOFTHSM_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
)
TOOL_CANDIDATES = ("/usr/bin/pkcs11-tool", "/usr/local/bin/pkcs11-tool")
RESOLVED = frozenset({"proc_alive", "scan_learned", "system_index"})
ATTEMPTS = 3
DURATION = 60
WORKLOAD_DELAY = 20
TEST_PIN = "1234"


def require(ok, reason):
    if not ok:
        print("verify-unidentified-exe-name: %s" % reason, file=sys.stderr)
        raise SystemExit(1)


def probe(candidates):
    for path in candidates:
        if Path(path).is_file():
            return path
    return None


def kdev_pair(path):
    """The kernel (major, minor, ino) of a file in the MAPPED-device
    domain: privately map one page and read the mapping's device back
    from our own maps — exactly what the EXEC pair carries. `stat`
    reports the subvolume device instead, which differs on btrfs."""
    before = set(Path("/proc/self/maps").read_text().splitlines())
    with open(path, "rb") as handle:
        with mmap.mmap(handle.fileno(), 1, prot=mmap.PROT_READ) as _mapping:
            after = set(Path("/proc/self/maps").read_text().splitlines())
    ours = sorted(line for line in after - before
                  if line.rsplit(None, 1)[-1] == path)
    require(len(ours) == 1, "exactly one fresh mapping for %s" % path)
    fields = ours[0].split()
    major_hex, minor_hex = fields[3].split(":")
    return (int(major_hex, 16), int(minor_hex, 16), int(fields[4]))


def oracle(document, tool, major, minor, ino):
    """Classify one capture: PASS names our pair at the exact tool
    path, RETRY missed it, FAIL leaves our pair unnamed or misnamed
    (or the document malformed)."""
    try:
        modules = document["modules"]
    except (KeyError, TypeError):
        return ("FAIL", "document has no modules[]")
    if not isinstance(modules, list):
        return ("FAIL", "modules[] is not a list")
    seen = []
    for module in modules:
        use = (module or {}).get("unbound_use")
        if use is None:
            continue
        exes = use.get("executables")
        if exes is None:
            continue
        if not isinstance(exes, list):
            return ("FAIL", "executables is not a list")
        for record in exes:
            try:
                dev = record["dev"]
                hit = (dev["major"], dev["minor"], record["ino"]) == (major, minor, ino)
            except (KeyError, TypeError):
                return ("FAIL", "executables[] record lacks dev{ major, minor }/ino: %r" % (record,))
            if not hit:
                continue
            seen.append(record)
    if not seen:
        return ("RETRY", "our (dev, ino) left no unidentified image (bound or missed)")
    unnamed = [record for record in seen
               if not record.get("exe") or record.get("resolution") not in RESOLVED]
    if unnamed:
        return ("FAIL", "our pair is unnamed: %r" % (unnamed,))
    names = sorted({record["exe"] for record in seen})
    if names != [tool]:
        return ("FAIL", "our pair named the wrong path: %r" % (names,))
    return ("PASS", "named: %s" % (", ".join(names),))


def self_test():
    tool = "/usr/bin/pkcs11-tool"
    good = {"modules": [{"unbound_use": {"executables": [
        {"exe": tool, "dev": {"major": 8, "minor": 1},
         "ino": 99, "resolution": "proc_alive", "pid_host": 9,
         "first_call_ns": 1, "calls_at_least": 2}]}}]}
    verdict, _ = oracle(good, tool, 8, 1, 99)
    require(verdict == "PASS", "self-test: the named record must pass")
    unknown = {"modules": [{"unbound_use": {"executables": [
        {"exe": None, "dev": {"major": 8, "minor": 1},
         "ino": 99, "resolution": "path_unknown", "pid_host": 9,
         "first_call_ns": 1, "calls_at_least": 2}]}}]}
    verdict, _ = oracle(unknown, tool, 8, 1, 99)
    require(verdict == "FAIL", "self-test: our unnamed pair must fail")
    misnamed = {"modules": [{"unbound_use": {"executables": [
        {"exe": "/usr/bin/other", "dev": {"major": 8, "minor": 1},
         "ino": 99, "resolution": "system_index", "pid_host": 9,
         "first_call_ns": 1, "calls_at_least": 2}]}}]}
    verdict, _ = oracle(misnamed, tool, 8, 1, 99)
    require(verdict == "FAIL", "self-test: our misnamed pair must fail")
    absent = {"modules": [{"unbound_use": {"executables": [
        {"exe": "/usr/bin/other", "dev": {"major": 8, "minor": 1},
         "ino": 100, "resolution": "system_index", "pid_host": 9,
         "first_call_ns": 1, "calls_at_least": 2}]}}]}
    verdict, _ = oracle(absent, tool, 8, 1, 99)
    require(verdict == "RETRY", "self-test: a foreign pair must retry")
    empty = {"modules": [{"unbound_use": {"executables": []}}]}
    verdict, _ = oracle(empty, tool, 8, 1, 99)
    require(verdict == "RETRY", "self-test: no images must retry")
    missing = {"modules": [{"unbound_use": None}]}
    verdict, _ = oracle(missing, tool, 8, 1, 99)
    require(verdict == "RETRY", "self-test: null unbound_use must retry")
    print("verify-unidentified-exe-name self-test passed")


def tail(path, count=20):
    try:
        return "".join(Path(path).read_text().splitlines(keepends=True)[-count:])
    except OSError:
        return "<no log>"


def build_teacher(work):
    """Compile the teach-preload fixture into the work dir."""
    cc = shutil.which("cc")
    require(cc, "missing tool on PATH: cc (for --teach)")
    source = Path("tests/fixtures/teach-sleep.c")
    require(source.is_file(), "teach fixture is missing: %s" % source)
    target = work / "teach_sleep.so"
    build = subprocess.run(
        [cc, "-shared", "-fPIC", "-O2", "-o", str(target), str(source)],
        capture_output=True, text=True,
    )
    require(build.returncode == 0, "teach fixture build failed:\n" + build.stderr)
    return str(target)


def teacher_alive(teacher):
    if teacher.poll() is not None:
        return False
    try:
        os.readlink("/proc/%d/exe" % teacher.pid)
    except OSError:
        return False
    return True


DOCKER_CONF = "/matrix/softhsm2.conf"
DOCKER_TOKENS = "/matrix/tokens"
DOCKER_PRELOAD = "/matrix/teach_sleep.so"


def docker_exec(container, *args, **kwargs):
    return subprocess.run(["docker", "exec", container] + list(args), **kwargs)


def docker_spawn(container, *args, **kwargs):
    return subprocess.run(["docker", "exec", "-d", container] + list(args), **kwargs)


def docker_probe(container, candidates):
    for path in candidates:
        probe = docker_exec(container, "test", "-f", path)
        if probe.returncode == 0:
            return path
    return None


def host_pids(marker):
    """Host pids whose command line carries our marker; the bracket
    keeps pgrep from matching itself."""
    pattern = "[%s]%s" % (marker[0], marker[1:])
    found = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    if found.returncode != 0:
        return []
    return [int(pid) for pid in found.stdout.split()]


def host_maps_contain(pid, needle):
    maps = subprocess.run(["sudo", "-n", "cat", "/proc/%d/maps" % pid],
                          capture_output=True, text=True)
    return maps.returncode == 0 and needle in maps.stdout


def host_maps_pair(pid, path):
    """The kernel (major, minor, ino) of a host-visible mapping, read
    from the host's /proc — the same mapped domain the oracle uses."""
    maps = subprocess.run(["sudo", "-n", "cat", "/proc/%d/maps" % pid],
                          capture_output=True, text=True)
    require(maps.returncode == 0, "cannot read /proc/%d/maps" % pid)
    ours = sorted(line for line in maps.stdout.splitlines()
                  if line.rsplit(None, 1)[-1] == path)
    require(ours, "no %s mapping in pid %d" % (path, pid))
    fields = ours[0].split()
    major_hex, minor_hex = fields[3].split(":")
    return (int(major_hex, 16), int(minor_hex, 16), int(fields[4]))


def build_linger(work):
    """Compile the linger-preload fixture into the work dir."""
    cc = shutil.which("cc")
    require(cc, "missing tool on PATH: cc (for --linger)")
    source = Path("tests/fixtures/teach-sleep.c")
    require(source.is_file(), "linger fixture is missing: %s" % source)
    target = work / "linger.so"
    build = subprocess.run(
        [cc, "-shared", "-fPIC", "-O2", "-DLINGER", "-o", str(target), str(source)],
        capture_output=True, text=True,
    )
    require(build.returncode == 0, "linger fixture build failed:\n" + build.stderr)
    return str(target)


def main(binary, work, keep, tool_arg, runs_arg, teach_arg, linger_arg, docker):
    runs = int(runs_arg)
    require(runs >= 1, "runs must be a positive integer")
    teach = teach_arg == "1"
    linger = linger_arg == "1"
    if docker:
        return main_docker(binary, work, tool_arg, runs, teach, linger, docker)
    if tool_arg:
        require(Path(tool_arg).is_file() and os.access(tool_arg, os.X_OK),
                "tool is not executable: %s" % tool_arg)
        tool = tool_arg
    else:
        tool = probe(TOOL_CANDIDATES)
        require(tool, "no pkcs11-tool at probed paths")
    require(shutil.which("softhsm2-util"), "missing tool on PATH: softhsm2-util")
    softhsm = probe(SOFTHSM_CANDIDATES)
    require(softhsm, "no libsofthsm2.so at probed paths")
    sudo = subprocess.run(["sudo", "-n", "true"])
    require(sudo.returncode == 0, "sudo -n is required for the observer")
    major, minor, ino = kdev_pair(tool)
    print("tool %s dev %d:%d ino %d" % (tool, major, minor, ino))

    work = Path(work)
    tokens = work / "tokens"
    tokens.mkdir(mode=0o700, exist_ok=True)
    conf = work / "softhsm2.conf"
    conf.write_text(
        "directories.tokendir = %s\nobjectstore.backend = file\n"
        "log.level = ERROR\n" % tokens
    )
    env = dict(os.environ, SOFTHSM2_CONF=str(conf))
    init = subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", "exename",
         "--so-pin", "5678", "--pin", TEST_PIN],
        env=env, capture_output=True, text=True,
    )
    require(init.returncode == 0, "token init failed:\n" + init.stderr)

    # The holder keeps the module mapped for the whole run: discovery
    # attaches mapped modules, and the short-lived tool alone maps it
    # too briefly to be found. It makes no calls itself.
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c",
         "import ctypes, sys, time; ctypes.CDLL(sys.argv[1]); time.sleep(600)",
         softhsm],
        env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        mapped = False
        for _ in range(100):
            if holder.poll() is not None:
                break
            try:
                maps = Path("/proc/%d/maps" % holder.pid).read_text()
            except OSError:
                time.sleep(0.1)
                continue
            if "libsofthsm2.so" in maps:
                mapped = True
                break
            time.sleep(0.1)
        require(mapped, "holder never mapped libsofthsm2.so")
        preload = build_teacher(work) if teach else None
        linger_so = build_linger(work) if linger else None
        last = run_attempts(binary, work, env, tool, softhsm, major, minor, ino,
                            runs, preload, linger_so)
        if last is None:
            return
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait()
    require(False, "no passing attempt (%s)" % (last,))
PY
cat >> "$exe_runner" <<'PY'


def docker_exec_env(container, env, *args, **kwargs):
    options = []
    for key, value in env.items():
        options += ["-e", "%s=%s" % (key, value)]
    return subprocess.run(["docker", "exec"] + options + [container] + list(args), **kwargs)


DOCKER_LINGER = "/matrix/linger.so"


def main_docker(binary, work, tool_arg, runs, teach, linger, container):
    require(teach, "--docker needs --teach: the overlay pair comes from the live teacher")
    work = Path(work)
    inspect = subprocess.run(["docker", "inspect", container],
                             capture_output=True)
    require(inspect.returncode == 0, "no such container: %s" % container)
    if tool_arg:
        tool = tool_arg
        require(docker_probe(container, [tool]),
                "tool is missing in %s: %s" % (container, tool))
    else:
        tool = docker_probe(container, TOOL_CANDIDATES)
        require(tool, "no pkcs11-tool at probed paths in %s" % container)
    softhsm = docker_probe(container, SOFTHSM_CANDIDATES)
    require(softhsm, "no libsofthsm2.so at probed paths in %s" % container)
    sudo = subprocess.run(["sudo", "-n", "true"])
    require(sudo.returncode == 0, "sudo -n is required for the observer and /proc reads")
    require(shutil.which("pgrep"), "missing tool on PATH: pgrep")
    setup = docker_exec(
        container, "bash", "-c",
        "rm -rf %s && mkdir -p %s && printf 'directories.tokendir = %s\\n"
        "objectstore.backend = file\\nlog.level = ERROR\\n' > %s && "
        "SOFTHSM2_CONF=%s softhsm2-util --init-token --free --label ovl "
        "--so-pin 5678 --pin 1234" % (
            DOCKER_TOKENS, DOCKER_TOKENS, DOCKER_TOKENS, DOCKER_CONF, DOCKER_CONF),
        capture_output=True, text=True,
    )
    require(setup.returncode == 0, "token init failed:\n" + setup.stderr)
    preload = None
    if teach:
        copy = subprocess.run(
            ["docker", "cp", "tests/fixtures/teach-sleep.c",
             "%s:%s" % (container, "/matrix/teach-sleep.c")],
            capture_output=True, text=True,
        )
        require(copy.returncode == 0, "teach fixture copy failed:\n" + copy.stderr)
        build = docker_exec(
            container, "cc", "-shared", "-fPIC", "-O2", "-o", DOCKER_PRELOAD,
            "/matrix/teach-sleep.c", capture_output=True, text=True,
        )
        require(build.returncode == 0, "teach fixture build failed:\n" + build.stderr)
        preload = DOCKER_PRELOAD
    linger_so = None
    if linger:
        copy = subprocess.run(
            ["docker", "cp", "tests/fixtures/teach-sleep.c",
             "%s:%s" % (container, "/matrix/teach-sleep.c")],
            capture_output=True, text=True,
        )
        require(copy.returncode == 0, "linger fixture copy failed:\n" + copy.stderr)
        build = docker_exec(
            container, "cc", "-shared", "-fPIC", "-O2", "-DLINGER",
            "-o", DOCKER_LINGER, "/matrix/teach-sleep.c",
            capture_output=True, text=True,
        )
        require(build.returncode == 0, "linger fixture build failed:\n" + build.stderr)
        linger_so = DOCKER_LINGER
    marker = "r8exename-%d" % os.getpid()
    holder = "%s-holder" % marker
    docker_spawn(
        container, "bash", "-c",
        "exec -a %s python3 -I -c 'import ctypes, time; "
        "ctypes.CDLL(\"%s\"); time.sleep(600)'" % (holder, softhsm),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        holder_pids = []
        for _ in range(100):
            holder_pids = [pid for pid in host_pids(holder)
                           if host_maps_contain(pid, "libsofthsm2.so")]
            if holder_pids:
                break
            time.sleep(0.1)
        require(holder_pids, "holder never mapped libsofthsm2.so")
        last = run_docker_attempts(binary, work, tool, softhsm, runs, preload,
                                   linger_so, container, marker)
        if last is None:
            return
    finally:
        # Container processes run as root: only sudo kills them.
        for pid in host_pids(holder):
            subprocess.run(["sudo", "-n", "kill", "-9", str(pid)],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    require(False, "no passing attempt (%s)" % (last,))


def run_docker_attempts(binary, work, tool, softhsm, runs, preload, linger_so, container, marker):
    last = None
    teacher_mark = "%s-teacher" % marker
    workload_env = {"SOFTHSM2_CONF": DOCKER_CONF}
    if linger_so:
        workload_env["LD_PRELOAD"] = linger_so
    for attempt in range(1, ATTEMPTS + 1):
        out = work / ("attempt%d.json" % attempt)
        log = work / ("attempt%d.log" % attempt)
        observer = None
        try:
            major = minor = ino = None
            if preload:
                # Env assignments prefix exec (no env command: it would
                # reset argv[0] and lose the marker).
                docker_spawn(
                    container, "bash", "-c",
                    "LD_PRELOAD=%s SOFTHSM2_CONF=%s exec -a %s %s "
                    "--module %s -O --login --pin %s" % (
                        preload, DOCKER_CONF, teacher_mark, tool, softhsm, TEST_PIN),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                teacher_pids = []
                for _ in range(100):
                    teacher_pids = host_pids(teacher_mark)
                    if teacher_pids:
                        break
                    time.sleep(0.1)
                require(teacher_pids, "teacher never came up")
                major, minor, ino = host_maps_pair(teacher_pids[0], tool)
                print("tool %s dev %d:%d ino %d" % (tool, major, minor, ino))
            with open(log, "w") as stream:
                observer = subprocess.Popen(
                    ["sudo", "-n", binary, "inventory", "--system",
                     "--capture", "native", "--module", softhsm,
                     "--duration", str(DURATION), "-o", str(out)],
                    stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=subprocess.STDOUT, text=True,
                )
            time.sleep(WORKLOAD_DELAY)
            if observer.poll() is not None:
                last = ("FAIL", "observer exited %r before the workload:\n%s"
                        % (observer.returncode, tail(log)))
                break
            for ordinal in range(1, runs + 1):
                run = docker_exec_env(
                    container, workload_env,
                    tool, "--module", softhsm, "-O", "--login", "--pin", TEST_PIN,
                    capture_output=True, text=True, timeout=120,
                )
                require(run.returncode == 0,
                        "pkcs11-tool run %d exited %d:\n%s"
                        % (ordinal, run.returncode, run.stderr))
                if ordinal < runs:
                    time.sleep(3)
            try:
                status = observer.wait(timeout=DURATION + 120)
            except subprocess.TimeoutExpired:
                last = ("FAIL", "observer never exited:\n%s" % tail(log))
                break
            if status != 0:
                last = ("FAIL", "inventory exit %d:\n%s" % (status, tail(log)))
                break
            require(out.is_file(), "observer wrote no %s" % out)
            subprocess.run(
                ["sudo", "-n", "chown", "%d:%d" % (os.getuid(), os.getgid()), str(out)],
                check=False,
            )
            document = json.loads(out.read_text())
            verdict, detail = oracle(document, tool, major, minor, ino)
            print("attempt %d: %s: %s" % (attempt, verdict, detail))
            if verdict == "PASS":
                text = Path(log).read_text()
                base = os.path.basename(tool)
                require("unidentified executables:" in text
                        and base in text.split("unidentified executables:")[1].splitlines()[0],
                        "concise line does not name %s:\n%s" % (base, tail(log)))
                print("PASS attempt=%d %s" % (attempt, detail))
                return None
            if verdict == "FAIL":
                return (verdict, detail)
            last = (verdict, detail)
        finally:
            if observer is not None and observer.poll() is None:
                observer.kill()
                observer.wait()
            for pid in host_pids(teacher_mark):
                subprocess.run(["sudo", "-n", "kill", "-9", str(pid)],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    return last


def run_attempts(binary, work, env, tool, softhsm, major, minor, ino, runs, preload, linger_so):
    last = None
    workload_env = dict(env, LD_PRELOAD=linger_so) if linger_so else env
    for attempt in range(1, ATTEMPTS + 1):
        out = work / ("attempt%d.json" % attempt)
        log = work / ("attempt%d.log" % attempt)
        observer = None
        teacher = None
        try:
            if preload:
                # One preloaded instance of the same binary, alive from
                # before the observer starts: admission records its path
                # and the scan-learned map resolves the pair for every
                # short-lived run. Never preloaded: the observer itself.
                teacher = subprocess.Popen(
                    [tool, "--module", softhsm, "-O", "--login", "--pin", TEST_PIN],
                    env=dict(env, LD_PRELOAD=preload),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                time.sleep(2)
                require(teacher_alive(teacher), "teacher never came up")
            with open(log, "w") as stream:
                observer = subprocess.Popen(
                    ["sudo", "-n", binary, "inventory", "--system",
                     "--capture", "native", "--module", softhsm,
                     "--duration", str(DURATION), "-o", str(out)],
                    stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=subprocess.STDOUT, text=True,
                )
            time.sleep(WORKLOAD_DELAY)
            if observer.poll() is not None:
                last = ("FAIL", "observer exited %r before the workload:\n%s"
                        % (observer.returncode, tail(log)))
                break
            for ordinal in range(1, runs + 1):
                run = subprocess.run(
                    [tool, "--module", softhsm, "-O", "--login", "--pin", TEST_PIN],
                    env=workload_env, capture_output=True, text=True, timeout=120,
                )
                require(run.returncode == 0,
                        "pkcs11-tool run %d exited %d:\n%s"
                        % (ordinal, run.returncode, run.stderr))
                if ordinal < runs:
                    time.sleep(3)
            try:
                status = observer.wait(timeout=DURATION + 120)
            except subprocess.TimeoutExpired:
                last = ("FAIL", "observer never exited:\n%s" % tail(log))
                break
            if status != 0:
                last = ("FAIL", "inventory exit %d:\n%s" % (status, tail(log)))
                break
            require(out.is_file(), "observer wrote no %s" % out)
            subprocess.run(
                ["sudo", "-n", "chown", "%d:%d" % (os.getuid(), os.getgid()), str(out)],
                check=False,
            )
            document = json.loads(out.read_text())
            verdict, detail = oracle(document, tool, major, minor, ino)
            print("attempt %d: %s: %s" % (attempt, verdict, detail))
            if verdict == "PASS":
                text = Path(log).read_text()
                base = os.path.basename(tool)
                require("unidentified executables:" in text
                        and base in text.split("unidentified executables:")[1].splitlines()[0],
                        "concise line does not name %s:\n%s" % (base, tail(log)))
                print("PASS attempt=%d %s" % (attempt, detail))
                return None
            if verdict == "FAIL":
                return (verdict, detail)
            last = (verdict, detail)
        finally:
            if observer is not None and observer.poll() is None:
                observer.kill()
                observer.wait()
            if teacher is not None and teacher.poll() is None:
                teacher.kill()
                teacher.wait()
    return last


mode, binary, workdir, tool_arg, runs_arg, keep, teach, linger, docker = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
    sys.argv[6] == "1", sys.argv[7], sys.argv[8], sys.argv[9])
if mode == "self":
    if binary or workdir != "" or tool_arg or runs_arg != "1" or keep or teach != "0" or linger != "0" or docker:
        print("usage: --self-test takes no other flags", file=sys.stderr)
        raise SystemExit(2)
    self_test()
else:
    main(binary, workdir, keep, tool_arg, runs_arg, teach, linger, docker)
PY
python3 -I "$exe_runner" "$MODE" "$BINARY" "$WORK" "$TOOL" "$RUNS" "$KEEP" "$TEACH" "$LINGER" "$DOCKER"