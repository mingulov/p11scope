# Comparable eBPF tool failure modes — research for release hardening

**Date:** 2026-09-01
**Method:** Independent research agent (Opus) over issue trackers, CVEs and postmortems
for Aya, libbpf/libbpf-rs, bcc/bpftrace, Falco, Tracee, Tetragon, Pixie, osquery,
Datadog agent, Sysdig, Parca/Pyroscope. Each candidate was checked against this tree
(`src/discovery/scan.rs`, `src/process.rs`, `crates/ebpf/src/main.rs`,
`crates/manifest/src/identity.rs`, `crates/discover/src/main.rs`), so "applies" /
"already handled" below is grounded in the code, not assumed.
**Consumes:** `docs/superpowers/specs/2026-09-01-release-requirements-and-goal.md` §3.

## Top 10 hardening checklist

1. **Stop hardcoding tracepoint offsets.** Parse `/sys/kernel/tracing/events/sched/*/format`
   at load, pass offsets via a config map, assert on mismatch. Site:
   `crates/ebpf/src/main.rs` (the tracepoint fields must come from the live
   `task/task_newtask` format, not literal offsets).
   In 6.16 `sched_process_free`'s `comm` became `__data_loc` and moved `pid` 24→12;
   the bcc precedent (PR #2812, RHEL-RT extra `common_*` fields) returned **silently
   wrong data** rather than an error.
2. **Verify the opened inode against the maps-line inode** before attributing a module.
   `scan.rs:687` opens `/proc/<pid>/root{path}`; the post-open check (`hint_gate`,
   `scan.rs:864-882`) compares only *size*, only for `--module` hints. Closes the whole
   rename/copy/swap bypass class (Falco #2203, libs #1111, CVE-2022-26316).
3. **Budget the maps read.** `scan.rs:778`'s `std::fs::read` sits outside
   `CaptureWorkBudget` and outside `MAX_OBJECT_BYTES`; Fedora/Ubuntu/Arch now default
   `vm.max_map_count` to 1048576 (~70–100 MB of text, reachable accidentally by a JVM
   or ES node). Cap bytes and candidate groups, emit a `scan_truncated` outcome.
   Optional 6.11+ fast path: `ioctl(PROCMAP_QUERY)` for file-backed VMAs only.
4. **Add `CAP_DAC_READ_SEARCH`** to the capability model (`src/doctor.rs:34-41` and the
   T1 tier table) — aya needs it for the tracefs mount check (bcc #4107, bpfman
   capabilities table). Drop `CAP_SYS_RESOURCE`: BPF memory is memcg-accounted at the
   5.15 floor, so the memlock bump is a no-op (but it now counts against a pod limit).
5. **Make the tier probe load the real program with real map sizes and actually attach.**
   Falco libs #3010: a probe sized to 1 CPU reported "supported" while the real load
   used `n_possible_cpus` and failed on ≥64-CPU hosts — "Events detected: 0" from a
   healthy-looking service.
6. **Ship an SELinux policy module**: `allow <domain> self:bpf { map_create map_read
   map_write prog_load prog_run };` plus `process:ptrace` against scanned domains and
   the output paths. Version-gate `capability2 { bpf perfmon }` (undefined on older
   policy — RHBZ 2046362). Test under Enforcing, not Permissive. `privileged: true` is
   not sufficient: `prog_run` is checked against the program's label (FCOS #881).
7. **Distinguish seccomp EPERM from capability EPERM** in diagnostics, and ship a
   Localhost seccomp profile adding `bpf` + `perf_event_open` to RuntimeDefault instead
   of recommending Unconfined. Docker gated both on `CAP_SYS_ADMIN` until 23.0, so
   `--cap-add BPF` produced a misleading "MEMLOCK may be too low" (moby #43374).
8. **Restate kernel support as "5.15.x, tested on <list>"** and add a load-only CI
   matrix. Verifier behaviour is not monotonic: a stable backport into 5.15.93 broke
   previously-loading Cilium programs with "program is too large"; LWN counts 73
   verifier fixes between 6.3 and 6.13. Log aya's `VerifierLog` on failure — aya
   reports verifier rejections as bare `EACCES` (aya #863).
9. **Bind the verdict to the loss counters.** In-kernel ring-loss counting is already
   better than most tools ship (`EVIDENCE_RING_LOSS`, `src/trace.rs:162`), but a lossy
   run must be distinguishable from a clean one at the consumer level, and a
   non-dumpable / hidepid / gone target must be a recorded expected outcome.
10. **For ia32: make userspace pointer stride a parameter.** Every
    `bpf_probe_read_user(x as *const u64)` in the uprobe path assumes 64-bit pointers.
    Determine ABI from the target's ELF class at exec and cache per-TGID —
    `in_ia32_syscall()` is invalid in uprobe context and always returns false. Parse
    maps addresses width-agnostically (compat `/proc/PID/maps` formatting has regressed
    before).

## Tier 1 — near-certain, code-confirmed

- **#1 tracepoint offsets** (checklist 1). OTel profiler #737, bcc PR #2812, bpftrace #999.
- **#2 32-bit pointer width** (checklist 10). Compat-ness is a per-syscall `TS_COMPAT`
  bit, not a task property; Tracee maintains `sys_32_to_64_map`.
- **#3 opened file ≠ mapped file** (checklist 2). Mitigating: `open_regular`
  (`crates/manifest/src/identity.rs:153`) pins with `O_PATH` then reopens via
  `/proc/self/fd/N`, so the final component is race-free, and `/proc/<pid>/root` magic-link
  semantics resolve against the *target's* root — the runc-escape class
  (CVE-2019-5736, CVE-2024-21626) is largely closed already. The gap is **identity**, not escape.
- **#4 vendor `dlopen` is a host-root primitive** (CVE-2019-14271, `docker cp`). Applies
  structurally to `crates/discover`, which exists to run vendor code. Already dropping
  uid/gid, clearing caps, verifying `PR_SET_NO_NEW_PRIVS` by re-read. Residual: the
  dropped-to identity is a real host user (`SUDO_UID`) and there is no seccomp/Landlock
  jail around the `dlopen`.
- **#5 ring-buffer drops invisible unless counted in-kernel** — aya sends drop
  notifications to the *program*, not the userspace reader. **Already handled**; the
  remaining gap is the verdict (checklist 9). Falco CVE-2019-8339 is the canonical case.

## Tier 2 — high likelihood

- **#6 `/proc/<pid>/maps` is non-atomic and can stall the target.** Generated page-by-page
  with `mmap_lock` dropped between pages; `dlopen` is exactly a split/merge storm.
  Measured on v5.4: target `mmap()` worst case 0.097 ms idle → 8020 ms median with 1000
  busy tasks. Single `std::fs::read` (`scan.rs:778`) is the right call already; add
  dedupe by (dev, inode) — `candidate_groups` already keys this way — and rate-limit scans.
- **#7 unbounded maps read** (checklist 3).
- **#8 tracefs DAC / `CAP_DAC_READ_SEARCH`** (checklist 4).
- **#9 Docker seccomp blocks `bpf()`** (checklist 7).
- **#10 SELinux `bpf` class + `process:ptrace`** (checklist 6).
- **#11 "5.15+" is not a supportable claim** (checklist 8). Good news: the program uses
  only `bpf_probe_read_user*` — no undifferentiated `bpf_probe_read` — so the 6.12
  tracepoint breakage (Falco libs #2736) does not hit us.
- **#12 tracefs automount deprecation vs the raw-tracepoint trade.** Since 6.17 the
  `/sys/kernel/debug/tracing` automount is behind `CONFIG_TRACEFS_AUTOMOUNT_DEPRECATED`.
  Raw-tp buys independence from tracefs and from offset drift, but sells a hard BTF+CO-RE
  dependency — and aya's CO-RE is the weakest part of the stack (#1662: flexible-array
  bounds check wrong in every released aya; #349: full CO-RE intrinsics not in rustc).
  Keeping both variants in one object (the parked 12→14 note) preserves both properties.
  **Do not lose the BTF-independence currently held for free.**

## Tier 3 — medium likelihood

- **#13 container ID from cgroup path is structurally unreliable** (falcosecurity/libs #63,
  Tetragon #540: `bpf_get_current_cgroup_id()` is cgroupv2-only). Confirms the existing
  MEDIUM "mutable cgroup pathname" finding as an industry-wide unsolved problem. Record
  the cgroup path as observed-at-time-T evidence with a mutability caveat, not identity.
- **#14 PID-namespace mismatch produces *wrong* attribution, not missing data**
  (pyroscope #3002, Datadog #1511). Require `hostPID: true` + host `/proc` and **verify at
  startup** (compare tracepoint-observed tgid against `/proc/self/status` `NSpid` depth);
  refuse to attribute if they disagree. Note `setns()` for mount namespaces cannot be
  called from a multithreaded process (bpfman split out a single-threaded helper).
- **#15 hardened `/proc`, Yama, non-dumpable targets are silent blind spots.** Sharp edge:
  security-conscious PKCS#11 consumers holding key material are exactly the processes
  most likely to set `PR_SET_DUMPABLE(0)` — the highest-value targets may be permanently
  unreadable. On gVisor/Kata the workload is not observable from the host at any
  privilege. `doctor` must probe procfs mount options and Yama `ptrace_scope` and report
  a degraded tier.
- **#16 aya 0.14-specific edges.** #1331 errno mangled below 6.8 (never match numeric
  errno from aya map ops); #1349 `BPF_BTF_LOAD` fails in Docker/GCP COS; #1628 pinned maps
  broke across an upgrade (don't pin); #1649 `--btf` relocation of `compiler_builtins`
  memcpy/memset → func_info mismatch (workaround: global `-Cdebuginfo=2`). Pinning
  `aya = "=0.14.0"` and building `--locked` is the right posture.
- **#17 Falco's silently-dead-driver critical** (GHSA-c7mr-v692-9p4g). "Attached and
  healthy" must be actively verified, not assumed — see checklist 5.

## Tier 4 — lower likelihood, cheap to close

- **#18 control characters in `/proc`-derived strings** (RUSTSEC-2025-0055, Splunk
  SVD-2023-0810). Partially applies: JSON via `serde_json` escapes correctly, but
  `scan.rs:836`'s `String::from_utf8_lossy(raw_path)` reaches `eprintln!`. Note the kernel
  does **not** escape backslashes in maps pathnames — only newlines as `\012` — so
  `foo\nbar` and a literal `foo\012bar` are indistinguishable, as are a real file named
  `libp11.so (deleted)` and a deleted one. Escape at capture, parse the pathname as
  "everything after the 5th whitespace field to end of line", never re-split.
- **#19 evidence-path symlink attack** (CVE-2025-27591, Meta's `below`). **Mostly handled**
  — `openat2(RESOLVE_NO_SYMLINKS)` at `src/output.rs:285` plus owner/sticky ancestry checks
  in `verify.rs:491-546`. Keep it; never add a convenience chmod.
- **#20 inherited file descriptors** (CVE-2024-21626 runc). Rust's `File::open` sets
  CLOEXEC, but raw `libc::open`/`openat` and `perf_event_open` do not (the latter needs
  `PERF_FLAG_FD_CLOEXEC`). A leaked BPF map fd into the privilege-dropped helper is a
  write primitive into our own kernel state. Assert `/proc/self/fd` in the helper.
- **#21 memfd / anonymous executable mappings** invisible to path matching. **Already
  handled correctly** — `scan.rs:846-852` records path-less groups as `Skipped` with
  `device M:m inode N`. Worth surfacing as an explicit "unidentifiable provider candidate"
  class, since some HSM vendors legitimately ship in-memory loaders.
- **#22 BPF map poisoning** (matheuzsecurity writeup; USENIX Sec '23 cross-container
  attacks). Applies to `PID_FILTER`/`SCOPE_AUTH`. Don't pin maps to bpffs (we don't).
  Document that granting p11scope is equivalent to granting node root: no exec into the
  pod, read-only rootfs, no service account token.

## Already better than the comparable tools

- The `PidPin` (pidfd + starttime) generation guard is Tetragon's `exec_id` idea done
  correctly.
- In-kernel ring-loss counters close the class that bit Falco (CVE-2019-8339).
- `openat2(RESOLVE_NO_SYMLINKS)` on the output path closes the class that bit `below`
  (CVE-2025-27591).

**Largest genuinely open risks: #1, #2, #3.**
