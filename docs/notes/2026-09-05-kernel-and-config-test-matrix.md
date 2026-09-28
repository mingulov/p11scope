<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Kernel and config test matrix

Written 2026-09-05. Every result in §2 was measured that day in local QEMU/KVM
VMs; anything not measured is marked. Supersedes the first draft of this file,
which recommended raising the kernel floor — that turned out to be unnecessary.
This is a dated experiment record. Current support and release qualification
are stated in the [operator guide](../usage.md#kernel-floor-and-unsupported-environments)
and [changelog](../../CHANGELOG.md#qualification-of-this-release).

## 1. Why this exists

Five defects were found in two days. Not one was catchable by the four Rust
gates, and four of the five were introduced in W3:

| Defect | Fixed | Why the gates could not see it |
| --- | --- | --- |
| `BPF_PROG_LOAD` → ENOTSUPP for every program | `56101fa` | Needs the privileged attach lane to run at all |
| Ordinary target exit published as a lost uprobe link | `b74a65d` | Needs a live attach with a target that exits mid-capture |
| Uninitialised struct padding rejected by pre-6.5 verifiers | `24f82d0` | Needs a 5.15 or 6.2 kernel; the dev box runs 7.0 |
| `doctor` reports T0 offline on a working RHEL 9 host | `c1e1192` | Needs a backported vendor kernel |
| uretprobe kills seccomp-filtered targets on affected kernels | **open**, measured §5 | Needs an affected kernel *and* a filtered target |

The shape is always the same: the workstation runs one kernel, CI runs one
kernel, and the supported range is far wider than either. The first thing a
matrix buys is not exotic coverage — it is **forcing the privileged e2e lane to
run somewhere on every change**, which is what caught the first two.

## 2. Measured results

Rows are `p11scope profile --pid <target> --mode metrics` against a process with
`libsofthsm2.so` mapped: a real load, attach and capture.

| Kernel | Distro | Before `24f82d0` | After |
| --- | --- | --- | --- |
| `5.14.0-741.el9` | CentOS Stream 9 (RHEL 9 rebuild) | not measured | **PASS** — 136/136, losses 0 |
| `5.15.0-187-generic` | Ubuntu 22.04 | FAIL — EACCES, `invalid read from stack off -72+3 size 8` | **PASS** — 136/136 |
| `6.2.0-39-generic` | Ubuntu 22.04 HWE | FAIL — identical | inferred PASS (**not re-measured**) |
| `6.5.0-45-generic` | Ubuntu 22.04 HWE | PASS — 136/136 | PASS |
| `6.8.0-137-generic` | Ubuntu 24.04 | PASS | PASS |
| `6.17.0-1022-azure` | Ubuntu 24.04, the CI runner | PASS | PASS, losses 0 |
| `7.0.0-30-generic` | the workstation | PASS | PASS, full e2e lane |

Config dimensions measured, all on `6.17.0-1022-azure` unless noted:

| Setting | Tested | Result |
| --- | --- | --- |
| `net.core.bpf_jit_harden` | `1`, `2` | PASS both, 136/136 |
| `kernel.perf_event_paranoid` | `4` (Ubuntu), `2` (CentOS) | PASS both |
| `kernel.yama.ptrace_scope` | `1`, `0` | PASS both |
| `CONFIG_BPF_JIT_ALWAYS_ON` | `y` | PASS; `y` on every kernel measured |
| Lockdown | `none` | Only state seen; `integrity`/`confidentiality` **not tested** |

## 3. The floor: capability, not version

The first draft of this document recommended moving the floor to 6.8, on the
evidence that 5.15 and 6.2 rejected the object. That recommendation is
**withdrawn**: the rejection was one struct's uninitialised padding, and naming
it (`24f82d0`) restored 5.15 without touching anything else.

**The floor stays 5.15**, and it is set by `bpf_get_attach_cookie`, which every
uprobe program calls — not by anything W3 added. The next constraints below it
are CMPXCHG (5.12), bpf2bpf-with-tail-calls on the x86-64 JIT (5.10), ring
buffer (5.8), `probe_read_user` (5.5) and rdonly+freeze (5.2), so 5.15 is
comfortably the binding one.

`uprobe_multi` needs 6.6, but it is a **runtime-optional optimisation**, not a
floor: at this experiment's revision it was deferred work, and p11scope attached
136 individual probes. The experiment recommended detecting and using the
optional capability where present rather than demanding it. Raising the floor to 6.6 to pre-buy it would
have cost Ubuntu 22.04, Debian 12 and the entire RHEL 9 population for a
performance feature nobody is using yet.

### The version gate was the actual bug

CentOS Stream 9 reports `5.14.0-741.el9` with cookies and the perf link
backported. Measured there: every capability probe passes and a real capture
attaches 136/136 probes — while `doctor` printed `capability tier: T0 offline`,
because `host_attach` required a `uname`-versus-floor comparison alongside the
three probes that had actually exercised the kernel.

Fixed in `c1e1192`: the tier is derived from the probes (map create, full
program load, real uprobe attach/detach). The version row stays as an
informational warning. A kernel that genuinely lacks the support fails the
probes, so nothing is lost — and vendor kernels, where the version number is
meaningless, now report what they can actually do.

**This generalises.** Any check of the form "is `uname` new enough" is wrong on
RHEL, SUSE, Amazon Linux and every other backporting vendor. Prefer probing.

### Documentation that is now false

- `README.md:124`, `docs/usage.md:326`: the floor is still 5.15, so these are
  right again — but `docs/usage.md:330`'s caveat that the number "was not
  re-derived against a live sub-5.15 kernel" should now say it was derived
  against live 5.15 and 5.14-el9 kernels on 2026-09-05.
- `docs/usage.md:326-328` says p11scope "does not runtime-check the kernel
  version". `doctor` does (`src/doctor.rs:135`). Stale.
- **The attach-failure hint names "missing BTF" as a cause. It is not one.** The
  BPF object has no `.BTF` section and aya treats vmlinux BTF as optional
  (`Btf::from_sys_fs().ok()`), so `CONFIG_DEBUG_INFO_BTF` is not a requirement.
  The hint, `docs/usage.md:345` and `docs/notes/phase5-unsupported.md` case 4 all
  send users to check something that cannot be the problem.

## 4. The matrix

**Owner amendment (2026-09-07):** native64 and ia32 are required axes of every
testable x86-64 kernel/configuration row below, including SHOULD/NICE rows
when run. Reuse the same applicable product oracles for both widths. Missing
IA32 execution prerequisites require explicit evidence and separate refusal
checks; they are not positive ABI qualification. Actual product failures stay
FAIL, and unexecuted positive checks stay UNRUN. See the
[current ABI limitations](../../CHANGELOG.md#known-limitations) and
`scripts/matrix/verify-ia32-compat.sh` for the reproducible compatibility lane.

### MUST — a release claim is false without it

| Cell | Obtain | Uniquely tests |
| --- | --- | --- |
| Ubuntu 22.04, **5.15** | Ubuntu 22.04 amd64 cloud image | The floor itself. Caught `24f82d0`. |
| Ubuntu 24.04, **6.8** | Ubuntu 24.04 amd64 cloud image | The mainstream LTS, and the host kernel of every container lane |
| Ubuntu 24.04, **6.17-azure** | `apt install linux-image-6.17.0-1022-azure` into the noble guest | The exact CI runner: turns a hosted red into a 40-second local reproduction |
| CentOS Stream 9, **5.14-el9** | `cloud.centos.org/centos/9-stream/.../GenericCloud-9-latest` | Backported vendor kernels, where version numbers lie. Caught `c1e1192`. |
| Ubuntu 24.04, **6.11.0-17** + filtered target | `apt install linux-image-6.11.0-17-generic` into the noble guest — it is in `noble-updates`, no mainline `.deb` needed | The only defect that *harms the observed process*: §5. Also the only cell proving a `uname` gate cannot express the affected set. |

Five cells, each able to block a release alone. The RHEL row earns MUST because
enterprise HSM users are the target population and because it is the only cell
that exercises "version says no, capability says yes". The 6.11.0-17 row earns
it because everything else in this document is p11scope failing; that row is
p11scope *destroying someone else's process* and reporting nothing.

### SHOULD

| Cell | Obtain | What it catches |
| --- | --- | --- |
| Debian 12, 6.1 | Debian cloud image | The most-deployed 6.x LTS; second sample of the pre-6.6 `regs.rip` loader path |
| Fedora current | Fedora 44 x86-64 cloud image | Newest verifier (rejections are non-monotonic in both directions), SELinux enforcing, upstream `perf_event_paranoid=2` |
| Lockdown `confidentiality` | `echo confidentiality > /sys/kernel/security/lockdown` on a throwaway overlay | `bpf_probe_read_kernel` becomes unavailable → `task_newtask` fails to load → the whole session fails, **including `--pid` scope where that program is never attached**. `doctor` reports lockdown as `Ok`. Misleading twice, never once induced. |
| cgroup v1 | `-append systemd.unified_cgroup_hierarchy=0` | `--cgroup` fails at `CgroupArray::set` with `Bad file descriptor` and a hint that blames caps, lockdown and the kernel floor — none of which is the cause |
| tracefs absent or 0700 | `umount /sys/kernel/tracing` | Lifecycle degradation; honest today, worth keeping honest |

### NICE

Alpine/musl (a packaging question first — no musl target is built), Amazon
Linux 2023, CentOS Stream 10, mainline `-rc` for early verifier warning,
custom builds with `CONFIG_BPF_JIT_ALWAYS_ON=n` or `CONFIG_UPROBE_EVENTS=n` to
prove the documentation, Debian 11 (5.10) to see the genuine below-floor message.

The ia32 axis is required by the owner amendment above; it reuses the matrix
with a `-m32` harness parameter rather than a separate set of kernel cells.

## 5. Measured: attaching a uretprobe kills a seccomp-hardened target

Measured 2026-09-05. Cell: `scripts/matrix/verify-uretprobe-seccomp.sh`, which
builds `scripts/matrix/uretprobe-seccomp-harness.c` — a target that arms a
seccomp allowlist deliberately omitting the uretprobe syscall, then calls a
probed function in a loop.

Linux 6.11 moved uretprobes to a syscall trampoline: when a probed function
returns, the kernel makes the **target** issue `__NR_uretprobe` (x86-64 nr 335)
from a trampoline page. A seccomp filter that does not allow 335 therefore
fires on a syscall the target never wrote. All five of p11scope's
`#[uretprobe]` programs are on this path.

| Kernel | uretprobe syscalls seen | Filtered target | Events delivered |
| --- | --- | --- | --- |
| `6.8.0-137-generic` | 0 — breakpoint trampoline, no syscall | survives | 40 |
| **`6.11.0-17-generic`** (noble HWE, 24.04.2) | 0 — killed before the tracepoint | **SIGSYS, dead** | **0** |
| `6.11.0-29-generic` (noble HWE, later SRU) | 40 | survives | 40 |
| `6.17.0-1022-azure` | 39 | survives | 39 |
| `7.0.0-30-generic` (workstation) | 40 | survives | 40 |

On the affected kernel, by the target's seccomp default action:

| Action | Outcome | Events |
| --- | --- | --- |
| `SECCOMP_RET_KILL_PROCESS` | **SIGSYS**, dead on the first return | 0 |
| `SECCOMP_RET_KILL_THREAD` | **SIGSYS**, dead on the first return | 0 |
| `SECCOMP_RET_ERRNO(EPERM)` | **SIGSEGV** — the trampoline never restores the return address | 0 |
| `SECCOMP_RET_LOG` | survives | 40 |
| entry-only `uprobe`, same filter | survives | 39 |

### What this settles

**The affected set is not a version range.** `6.11.0-17` is affected and
`6.11.0-29` is clean: same upstream minor, same distro, same series, one SRU
apart. The upstream fix (`cf6cb56ef244`, "seccomp: passthrough uretprobe
systemcall", 6.14-rc2) is backported at a cadence no version comparison can
model. A `uname` gate would be wrong in both directions — exactly the defect
`c1e1192` fixed in `doctor` (§3). **Only probing answers this.**

**"Warn in the docs" is not sufficient.** The tool kills the process it is
observing, on the first return, and collects **zero events** in exchange. The
`errno` row is worse than the kill rows: an operator who sets
`SystemCallErrorNumber=EPERM` precisely to avoid being killed gets a
**segfault** that looks like a crash in their own application.

**Entry-only probing is a working fallback**, measured: the same filter, the
same kernel, 39 hits delivered, target alive. Degrading to entry probes costs
return values and latency and keeps call counts — strictly better than either
killing the target or refusing to run.

**The cheap pre-check is `/proc/<pid>/status`.** `Seccomp: 2` means a filter is
installed. It does not say whether that filter allows 335 (reading the target's
filter needs `PTRACE_SECCOMP_GET_FILTER`, too invasive), so the honest rule is:
affected kernel **and** filtered target → degrade, do not attach uretprobes.
Unfiltered targets — the common case — pay nothing.

### The fix, implemented 2026-09-06

`src/uretprobe_hazard.rs`, verified on `6.11.0-17` (affected) and `7.0.0-30`
(clean), all three layers end to end:

1. **A signalled death is never reported as an exit.** `run` owns its child, so
   a SIGSYS or SIGSEGV during capture is named, and the kernel is only consulted
   for those two shapes. With no probe attached it says so instead of taking
   blame it has not earned. `--pid` cannot read a non-child's status, so the
   asymmetry is stated rather than papered over: it reports that the target went
   away and that the capture knowingly carried the risk.
2. **A confined target is refused before a probe is installed.** The cheap check
   comes first — `/proc/<pid>/status` `Seccomp:` — so an unconfined target, the
   common case, never pays for the self-probe.
   `--allow-uretprobe-on-confined-target` is the operator's override, and it
   warns with exactly the reason it would have refused with. `--cgroup` attaches
   process-wide, so its targets cannot be enumerated and it is treated as
   possibly confined.
3. **The verdict comes from the mechanism, never from `uname`.** The self-probe
   forks a child, gives it a one-syscall denylist, attaches a real `p11_return`
   uretprobe to it, and reads how it died. The victim is always our own child.
   `doctor` reports it as `uretprobe vs seccomp` — informational, and
   deliberately not a `capability_tier` input, since an affected kernel captures
   perfectly from any unconfined target.

Guarded by `the_uretprobe_hazard_is_never_decided_by_a_kernel_version` and
`the_uretprobe_hazard_row_is_not_a_capability_tier_input`, both
mutation-verified.

Measured end to end on `6.11.0-17` with a seccomp-confined process that maps
`libsofthsm2.so`: refused by default and the target lives; under the override
p11scope attaches 136/136 probes and kills it, leaving the call in flight — the
defect reproduced through the real tool, and the reason the default is refusal.

**Still open:** entry-only degradation. `attach_targets_with` requires a slot's
return link before its entry link, and `in_flight = entered - returned` feeds
the completeness lattice, so attaching entry-only would report every call as
permanently in flight — "the call never returned" rather than "returns were not
observed". That needs a distinct capture state, which is a schema question, not
a patch.

## 6. What a cell runs, and where CI fits

### Per cell

| Command | Catches | Status |
| --- | --- | --- |
| `sudo p11scope doctor` and assert the tier line | Loads all 13 programs, attaches a real uprobe. **Would have caught `56101fa` and `c1e1192`** in seconds, without a PKCS#11 target. | exists |
| `scripts/verify-attach-e2e.sh` | Caught `b74a65d` and `24f82d0`. The only lane that loads *and* attaches *and* watches a target exit. | exists; needs a `P11SCOPE_BIN` override so a prebuilt binary can be used instead of an in-guest `cargo build` |
| `scripts/verify-inspect-doctor.sh` | Unprivileged, seconds, scope-agnostic | exists |
| `scripts/matrix/verify-uretprobe-seccomp.sh` | Classifies the kernel AFFECTED/CLEAN for §5. Needs no PKCS#11 target and no p11scope build — `cc` plus `bpftrace`. Its `--self-test` needs only `cc`, runs in hosted CI, and fails if the harness stops being able to detect a kill. | exists, §5 |
| environment fingerprint | Records `uname`, lockdown, `bpf_jit_*`, relevant `CONFIG_*`, cgroup and tracefs mounts, glibc, binary hash. Records, never asserts — it is what makes a pass or fail interpretable a month later. | to write, ~20 lines |

The ~20 `--self-test` oracles are deliberately **excluded** from a cell: they
validate scripts against their own constants and are kernel-independent, so they
buy nothing per cell. Hosted CI already runs them.

`scripts/matrix/` is a *deployment-shape* axis (docker, kind, knative, fork
scope, shared layers) on one host kernel. This is an orthogonal *kernel* axis.
Do not cross-product them — run the cheap systemd-only lanes per kernel and keep
the container lanes on one guest.

### CI/CD

Three tiers, matching how fast each needs to be:

1. **Per PR — unchanged.** Hosted CI already runs the four gates, every
   self-test, and `verify-attach-e2e.sh` on the runner's own kernel. That is one
   cell, it is the cell CI can run natively, and it is what caught two of the
   five defects. Nothing here should get slower.
2. **Nightly or pre-release — the matrix.** GitHub-hosted Linux runners expose
   `/dev/kvm`, so the same QEMU recipe in §7 runs there; a four-cell MUST sweep
   is a few minutes of runner time and does not belong on every push. Fail the
   job on any cell regression, and publish the fingerprints as artifacts so a
   later failure can be compared against what the kernel actually was. **Not
   verified**: that hosted runners have `/dev/kvm` enabled for this repo's
   plan — check before designing around it, and fall back to TCG (slower, still
   correct) or a self-hosted runner if not.
3. **Always, in the unit suite — the cheap invariants.** Three of the five
   defects reduce to something a compile-time or unit check catches once the
   mechanism is known, and those are already in place: the `offset_of!(_pad)`
   assertion (`crates/ebpf/src/main.rs`), the deferred-freeze rule and its
   contract guard, the leader-exit settlement tests, and the tier test that pins
   a backported kernel. That is the right division of labour — **the VM matrix
   finds the class of defect once; a unit test keeps it found.** Every matrix
   failure should end with a test that fails without a VM.

## 7. Reproducing a kernel control

The commands below describe the historical Ubuntu 22.04 control. Set
`P11SCOPE_VM_BASE` to an absolute path to a prepared qcow2 base, and place
your NoCloud seed files in the new private work directory before starting
the HTTP server. Verify that the selected ports are unused. Run only VMs
you own and retain their pidfile, logs and overlay until cleanup is verified.

```sh
: "${P11SCOPE_VM_BASE:?set the absolute path to a prepared qcow2 base}"
P11SCOPE_VM_WORK=$(mktemp -d /var/tmp/p11scope-vm.XXXXXX)
qemu-img create -f qcow2 -F qcow2 \
  -b "$P11SCOPE_VM_BASE" "$P11SCOPE_VM_WORK/overlay.qcow2" 20G
# Populate $P11SCOPE_VM_WORK with your NoCloud seed before continuing.
python3 -m http.server 18191 --bind 127.0.0.1 --directory "$P11SCOPE_VM_WORK" &
qemu-system-x86_64 -accel kvm -cpu host -machine q35 -m 2048 -smp 4 \
  -drive "file=$P11SCOPE_VM_WORK/overlay.qcow2,if=virtio,format=qcow2" \
  -netdev user,id=n1,hostfwd=tcp:127.0.0.1:2251-:22 -device virtio-net-pci,netdev=n1 \
  -smbios 'type=1,serial=ds=nocloud;s=http://10.0.2.2:18191/' \
  -display none -serial "file:$P11SCOPE_VM_WORK/serial.log" -daemonize \
  -pidfile "$P11SCOPE_VM_WORK/qemu.pid"
```

Four facts make this cheap, and each cost time to learn:

- **One host build runs on every cell.** The binary needs at most `GLIBC_2.34`
  (`objdump -T`); jammy has 2.35 and CentOS 9 has exactly 2.34. No guest needs a
  Rust toolchain. If a change ever raises that requirement above 2.34, this
  breaks and the matrix silently narrows to the build host's distro — worth a
  check in `build-release.sh`.
- **Kernels are apt packages.** One jammy guest reached 5.15, 6.2, 6.5 and 6.8;
  one noble guest reached the runner's exact `6.17.0-1022-azure`. One VM covers
  a column.
- **`grub-reboot` needs the full submenu path**, e.g.
  `gnulinux-advanced-<uuid>>gnulinux-5.15.0-187-generic-advanced-<uuid>`. The
  short form silently does nothing and the guest returns on the newest kernel —
  which reads exactly like a pass on the kernel you meant to test.
- **Output paths are checked.** p11scope refuses an output directory with a
  writable ancestor (`/tmp/...`, a writable checkout directory) with `output directory
  ancestor ... is untrusted: writable`. Write evidence to a root-owned path
  inside the guest.

## 8. What this does not establish

- The uretprobe/seccomp range in §5. Inferred from commit dates, not measured.
- Lockdown `integrity` or `confidentiality`, cgroup v1, musl, non-x86-64. Listed,
  not measured.
- Whether 6.2 passes after `24f82d0`. Inferred from 5.15 passing; not re-measured.
- Whether any program *after* `interface_return` also failed on 5.15 before the
  fix. Programs load alphabetically, so the run stopped there and later programs
  were never reached.
- Runtime correctness beyond "attached and captured" for the ad-hoc smoke test.
  `verify-attach-e2e.sh` checks evidence; a bare `profile` run does not.
