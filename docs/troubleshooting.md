<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Troubleshooting

When a live command refuses or a capture looks empty, start with
`p11scope doctor` (as the same identity you capture with, usually
`sudo p11scope doctor`): it names the failing check and the next step.
Each section below shows the exact line you see, why it happens, and
the fix. Lines marked "observed" are real output from the v0.6.0
release binary; shapes marked "documented" come from the cited product
text and notes and were not induced on the capture host (Ubuntu 26.04, kernel
7.0.0-38, `perf_event_paranoid=4`, lockdown `integrity`,
Secure Boot enabled).

## Live capture refuses: no privilege

What you see (observed, unprivileged `inventory --system`, exit 1):

```
p11scope: inventory --system: live capture needs root: the kernel refused to load p11scope's BPF programs (Operation not permitted). Run with sudo, or use 'p11scope inspect --pid N' for a scan without capture.
```

`doctor` without privileges agrees (observed, exit 1):

```
verdict: capture unavailable; inventory capture unavailable (preparing Inventory: LoadObject: loading fresh Inventory object with exact capacity: map error: failed to create map: Operation not permitted (os error 1)); run startup capture not in this build (run reports stay partial; run itself works)
effective capabilities ............ warn  none — live capture needs root
BPF map create .................... FAIL  loading BPF object with required task storage: map error: failed to create map `TASK_COOKIE`: Operation not permitted (os error 1)
uprobe-multi attach (own libc) .... FAIL  live capture needs root: the kernel refused to load p11scope's BPF programs (Operation not permitted). Run with sudo, or use 'p11scope inspect --pid N' for a scan without capture.
Next: run as root: sudo p11scope doctor.
```

(The failing map name varies run to run; the cause is the same
`Operation not permitted`.)

Why: loading BPF needs `CAP_BPF` (or `CAP_SYS_ADMIN`, which covers the
BPF/perf checks); this process has neither. Fix: capture as root
(`sudo p11scope ...`), or grant the documented capability set and
re-check with `doctor` — see
[privileges, per environment](usage.md#privileges-per-environment).
Without any live gate, `inspect`, `inventory --capture scan`,
`inventory diff`, help and version still work.

## `perf_event_paranoid=4` refuses `perf_event_open` (Ubuntu/Debian)

What you see (observed, unprivileged `doctor -v` on Ubuntu,
`perf_event_paranoid=4`):

```
kernel.perf_event_paranoid ........ warn  4 — uprobes need CAP_SYS_ADMIN on this host
```

With privileges the same row reads (observed, `sudo doctor -v`):

```
kernel.perf_event_paranoid ........ ok    4 — does not gate static uprobe-multi links, but refuses every perf_event_open without CAP_SYS_ADMIN (CAP_PERFMON does not lift it): the uretprobe self-probe (--cgroup, --system, run, confined --pid targets) and live-discovery loader/export probes; this process has CAP_SYS_ADMIN
```

Why: at paranoid 3 and above every `perf_event_open` needs
`CAP_SYS_ADMIN`; `CAP_PERFMON` does not lift it. That gates only an
explicit `--attach-backend singles` fallback now (and, on kernels
without a proven uprobe-multi pid filter, the dynamic loader/export
probes): the static probes, the self-probe and (where the pid filter
is proven) the live-discovery probes attach through uprobe-multi
links, which paranoid does not gate (the v0.6.0 row above still names
the self-probe and live-discovery probes; they moved to uprobe-multi
links since). Fix:
capture as root (`sudo p11scope ...`), or grant the five-capability
minimal set (`CAP_BPF`, `CAP_CHECKPOINT_RESTORE`,
`CAP_DAC_READ_SEARCH`, `CAP_PERFMON`, `CAP_SYS_PTRACE` — no
`CAP_SYS_ADMIN`) and re-check with `doctor` —
see [Run without sudo](usage.md#run-without-sudo). The measured
capability matrices are in
[privileges, per environment](usage.md#privileges-per-environment).

## Kernel too old: no `uprobe_multi`

What you see (documented shape, from the host gate in
`src/attach/multi_host.rs` and
[the unsupported-environments note](notes/phase5-unsupported.md)):
on a kernel whose self-link probe fails with the known pre-Multi
shape (observed on Linux 6.1), live capture refuses before loading
any capture program, and `doctor` skips the capture-object loads:

```
skipped: this check loads capture programs, which need uprobe-multi
```

with the verdict staying `capture unavailable` and the version hint
in the `Next:` step. See
[live host capability](usage.md#live-host-capability-and-unsupported-environments).

Why: live capture requires usable `uprobe_multi` load and self-link
capability, normally Linux 6.6+ or a working backport; capability is
tested, never admitted by version. Fix: boot a 6.6+ kernel (the
release is qualified on 6.6 through 7.3;
[qualification record](../CHANGELOG.md#qualification-of-this-release)),
or stay with the offline commands (`inspect`, `inventory --capture
scan`, `inventory diff`), which do not need the live gate.

## Missing BTF

What you see (documented shape): the `doctor` row for
`/sys/kernel/btf/vmlinux` warns with the open error, and a live
attempt fails in the early load branch with the actionable hint
(`UNSUPPORTED_ENV_HINT` in `src/attach.rs`):

```
hint: this usually means the environment cannot load or attach BPF programs at all — missing capabilities from the minimal live-capture set (CAP_BPF, CAP_CHECKPOINT_RESTORE, CAP_DAC_READ_SEARCH, CAP_PERFMON, CAP_SYS_PTRACE), a kernel lockdown mode, an LSM policy or a container seccomp profile, unavailable required BPF features, missing BTF (/sys/kernel/btf/vmlinux), or a restrictive kernel.perf_event_paranoid sysctl. See docs/notes/phase5-unsupported.md for what each looks like when observed. Run `p11scope doctor` to see which cause applies on this host.
```

Why: the BPF loader needs kernel BTF (`CONFIG_DEBUG_INFO_BTF` in the
running kernel's build). This shape was not induced on the capture
host (BTF is present there); it is the weakest-verified claim in the
[unsupported-environments note](notes/phase5-unsupported.md), kept
honest there. Fix: boot a kernel built with BTF (most distro
kernels qualify; check that `/sys/kernel/btf/vmlinux` exists), then
re-run `doctor`.

## Kernel lockdown refuses BPF

What you see: `doctor -v` always names the active mode (observed on
the capture host):

```
lockdown .......................... ok    integrity
```

Under a restrictive lockdown mode a live attempt fails with a
permission-shaped refusal (the same early-failure branch and hint as
above); lockdown is named in the hint. Why: lockdown can block BPF
loading and `perf_event_open` inside the kernel's own checks. This
host runs lockdown `integrity` with Secure Boot enabled and root
capture still works (observed: `verdict: capture available`), so
`integrity` alone is not a refusal. Fix: read the mode from the
`doctor` row or `/sys/kernel/security/lockdown`; if a restrictive
mode refuses the capture, relax the lockdown boot policy or capture
on a host without it.

## Secure Boot hosts

There is no Secure Boot check in p11scope and no Secure Boot error
line: Secure Boot matters only because SB-enabled systems typically
boot with kernel lockdown engaged (previous section). Observed
on the capture host: `mokutil --sb-state` reports
`SecureBoot enabled`, lockdown reads `integrity`, and
`sudo p11scope doctor`
reports `verdict: capture available` — Secure Boot alone does not
block a privileged capture. If a capture refuses on an SB host, work
through the lockdown and no-privilege sections above; the fix is a
boot-policy change or another host, not a p11scope flag.

## Cgroup capture sees no processes (no `hostPID`)

What you see (documented as DR-K8S-5 under
[Scopes (cgroup and pod)](known-limitations.md#scopes-cgroup-and-pod)):
without `hostPID` the observer resolves the pod cgroup but sees none
of its processes; capture exits 0 with "no PKCS#11 modules
discovered" and 0 probes, not naming the PID-visibility cause. Why:
the observer's `/proc` has no entries for the cgroup members, so
there is nothing to scan. Fix: run with `hostPID: true` on real
nodes (see [PID namespaces](usage.md#pid-namespaces)), or capture
the target's cgroup with the observer in the initial PID namespace.

## Related docs

- [Operator's guide](usage.md#quickstart): quickstart and full
  command reference.
- [Privileges, per environment](usage.md#privileges-per-environment):
  capability roles and the measured matrices.
- [Live host capability](usage.md#live-host-capability-and-unsupported-environments):
  the admission gate and historical refusal measurements.
- [Known limitations](known-limitations.md): every disclosed capture
  limit, including the one-shot shapes.
