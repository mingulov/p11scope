# Kernel and config test matrix

Written 2026-09-05, after three defects in a row that were invisible on the
developer's own machine. Every result in §2 was measured in a local QEMU/KVM VM
on that day; everything not measured is marked as such.

## 1. Why this exists

Three defects shipped into `main` during W3 and none was catchable by the four
Rust gates, because all three depend on the kernel the binary runs against:

| Defect | Fixed | Why local gates could not see it |
| --- | --- | --- |
| `BPF_PROG_LOAD` → ENOTSUPP for every program | `56101fa` | Needs a kernel that takes the rdonly-array constant-fold path — but see §2.1, it broke *every* kernel and was still missed |
| Ordinary target exit published as a lost uprobe link | `b74a65d` | Needs a live attach with a target that exits mid-capture |
| Kernel floor regressed from 5.15 to >6.2 | see §3 | Needs a 5.15 kernel; the dev box runs 7.0 |

The common shape: the workstation runs one kernel, CI runs one kernel, and the
supported range is much wider than either. A matrix is the only thing that
closes that gap, and it is now cheap — see §6.

## 2. Measured results

All rows are `p11scope profile --pid <target> --mode metrics`, a real attach
against a process with `libsofthsm2.so` mapped. "PASS" means the session
attached and captured; probe counts are quoted where taken.

### 2.1 Current `main` (`c4725c6`)

| Kernel | Distro | Result |
| --- | --- | --- |
| `5.15.0-187-generic` | Ubuntu 22.04 | **FAIL** — `interface_return` rejected, `os error 13` (EACCES), `invalid read from stack off -72+3 size 8` |
| `5.19`, `6.0`–`6.1` | — | **not measured** (inferred FAIL: same verifier era as 6.2) |
| `6.2.0-39-generic` | Ubuntu 22.04 HWE | **FAIL** — identical rejection |
| `6.5.0-45-generic` | Ubuntu 22.04 HWE | PASS — 136/136 probes attached |
| `6.8.0-137-generic` | Ubuntu 24.04 | PASS |
| `6.17.0-1022-azure` | Ubuntu 24.04, the GitHub runner | PASS |
| `7.0.0-30-generic` | the workstation | PASS |

**The true floor is above 6.2 and at or below 6.5.** The exact boundary is not
established; nothing between 6.2 and 6.5 ships in a distro we test, so narrowing
it needs mainline builds and is only worth doing if a precise number goes into
the support claim.

### 2.2 The floor is a regression, not a stale claim

Measured A/B on one machine, one boot of `5.15.0-187-generic`:

```
p11scope-prew3 (ae8494d, pre-W3) -> EXIT=0 | 136/136 probes attached
p11scope       (c4725c6, today)  -> EXIT=1 | loading interface_return, os error 13
```

`README.md:219` records that `ae8494d` passed a 5.15 campaign. That is now
independently confirmed on a live 5.15 kernel, and current `main` fails on the
same kernel minutes later. The `interface_*` programs existed at `ae8494d`
already, so W3 changed their bodies into something the older verifier rejects.
The rejection is a genuine verifier refusal (EACCES with a message), not the
silent ENOTSUPP class of `56101fa`.

### 2.3 Pre-fix behaviour, for contrast

The binary before `56101fa` failed with `os error 524` on `7.0.0-30-generic`,
`6.17.0-1022-azure` and `6.8.0-137-generic` alike. That defect was never
kernel-specific; it was found by CI only because CI is where the attach lane
actually ran.

### 2.4 Config dimensions measured

| Setting | Value tested | Result |
| --- | --- | --- |
| `net.core.bpf_jit_harden` | `1` and `2` | PASS both, 136/136 probes (6.17-azure) |
| `net.core.bpf_jit_enable` | `1` | PASS |
| `kernel.perf_event_paranoid` | `4` | PASS (both runner and VMs) |
| `kernel.yama.ptrace_scope` | `1` | PASS |
| `CONFIG_BPF_JIT_ALWAYS_ON` | `y` | PASS (present on every kernel measured) |
| Lockdown | `[none]` | Only state observed; integrity/confidentiality **not tested** |

JIT hardening was an early suspect for the ENOTSUPP defect and is now ruled out
by measurement in both directions.

## 3. The floor decision

**Owner decision, 2026-09-05: the supported floor moves to 6.8.** Restoring 5.15
is not worth the effort, so the floor becomes a stated platform choice instead
of a regression to chase.

Why 6.8 rather than 6.5, the lowest kernel measured passing:

- **6.8 is Ubuntu 24.04 LTS** — the platform the project already builds, tests
  and runs CI on. A floor that matches a real LTS is one users can check against
  their distro rather than their `uname`.
- **`uprobe_multi` needs 6.6.** The multi-uprobe link landed in Linux 6.6. It is
  deferred work today (ROADMAP.md:659 keeps it a separate optimisation, and
  p11scope currently attaches 136 individual probes), but a 6.8 floor pre-buys
  it: whoever picks it up will not have to move the floor again to do so.
- **6.5 buys nothing.** No LTS ships it — it was an interim Ubuntu 22.04 HWE
  kernel — and it sits below `uprobe_multi`. Choosing it would put the floor on
  the exact edge of what was measured, which is where folklore starts.

### What the decision costs

These platforms become explicitly unsupported (distro-to-kernel mapping is
**inferred**, not measured): Ubuntu 22.04 with its stock 5.15, Debian 12 (6.1),
RHEL 9 and rebuilds (5.14), Amazon Linux 2023 (6.1). That is most of the current
enterprise Linux base, and it should be a deliberate, stated choice rather than
something a user discovers from a verifier error.

### What the decision does not excuse

Two items are now required work, and neither is optional just because the floor
moved:

1. **Correct every published floor claim.** `README.md:124`, `docs/usage.md:326`
   and the attach-failure hint (`src/attach.rs`, quoted at
   `docs/notes/phase5-unsupported.md:63`) all say `>= 5.15`. Also
   `README.md:16`, `README.md:219`, `docs/usage.md:12`, `:150`, `:202`, `:330`
   and `:495`, which describe a 5.15 qualification campaign that no longer
   describes this code. `docs/usage.md:330` conceded the number "was not
   re-derived against a live sub-5.15 kernel"; it has now been derived and it is
   wrong, so the concession has to go too.
2. **Make a below-floor kernel fail legibly.** On 5.15 today the user gets
   `os error 13` plus a hint naming caps, lockdown, BTF and `perf_event_paranoid`
   before the kernel floor — four things that are fine — and the floor it names
   is the wrong number. A user on Debian 12 will hit exactly this. p11scope
   should detect the kernel version up front and say so plainly. `doctor`
   already classifies capability tiers (`src/doctor.rs:34`) and is the natural
   place for it.

Item 2 is what turns the floor from a number in a README into something the
program itself enforces, and it is the only reason 5.15 stays in the MUST tier
below — as a negative test, not as a supported platform.

## 4. The matrix

Justification is per row; entries without one do not belong here.

### MUST — a release claim is false without it

| Cell | Obtain | What only this catches | Cost |
| --- | --- | --- | --- |
| Ubuntu 24.04, kernel **6.8** | `p11scope-ws/vm-bases/noble` (held) | **The declared floor.** If this cell fails the support claim is false by definition | ~3 min |
| Ubuntu 24.04, kernel **6.17-azure** | `apt install linux-image-6.17.0-1022-azure` into the noble guest | The exact CI runner, so a hosted failure is reproducible locally in 40 seconds instead of a 12-minute push cycle | ~3 min |
| Ubuntu 22.04, kernel **5.15** — *negative* | `p11scope-ws/vm-bases/jammy` (held) | That a below-floor kernel fails **legibly**: names the kernel, names the floor, does not blame caps or BTF. This cell asserts the error message, not the capability | ~3 min |

Each row must be able to block a release on its own, which is why there are
three. 6.8 is the floor, 6.17-azure is the pipeline's own kernel, and 5.15 is
the first thing a Debian 12 or RHEL 9 user will experience.

The 5.15 row is the unusual one: it is expected to **fail**, and it passes the
matrix when it fails for the right reason with the right message. A cell like
that is easy to let rot, so its oracle should be the message text, not the exit
code.

Measured margin: 6.5 passes and 6.2 does not (§2.1), so the declared 6.8 floor
sits about two releases above the last kernel known to reject the object. That
margin is deliberate — it means an ordinary verifier-sensitive change does not
immediately break the floor — and §2.1's 6.2/6.5 boundary is worth re-measuring
whenever the eBPF source changes shape, because the margin is what absorbs it.

### SHOULD — realistic environments, low cost, defect likely

| Cell | Obtain | What it catches |
| --- | --- | --- |
| Debian 12, kernel 6.1 | Debian cloud image | Now **below the floor**, so this is a second negative cell: the most common non-Ubuntu server, where the refusal message is the entire user experience |
| RHEL-family via CentOS Stream 9, kernel 5.14 | CentOS Stream cloud image | A *backported* kernel, where the version number does not predict verifier behaviour. The one cell that can show the floor is a poor proxy: 5.14-with-backports may well accept what stock 6.2 rejects, which would mean the floor check should test capability, not `uname` |
| Fedora current | `p11scope-ws/vm-bases/fedora44-base` (held) | Newest verifier, different config defaults, non-Debian packaging of softhsm |
| Ubuntu 24.04 + HWE rolling kernel | `linux-image-generic-hwe-24.04` | Where the floor's users actually land as 24.04 ages, and the first place a future verifier change will bite |
| Lockdown = `integrity` | boot param `lockdown=integrity` on any held VM | `docs/notes/phase5-unsupported.md` lists lockdown as a documented failure mode that has **never been induced**. It is cheap to induce here. |
| cgroup v1 | `systemd.unified_cgroup_hierarchy=0` | `Scope::Cgroup` and `CGROUP_ARRAY` assume v2 layout |

### NICE — breadth and future-proofing

| Cell | Why it is not higher |
| --- | --- |
| Alpine / musl | No musl target is built today; this is a packaging question first |
| Amazon Linux 2023, Azure/GCP vendor kernels | Vendor kernels carry patches — the bottlerocket precedent (`ENOTSUPP` on a vendor kernel, unreproducible on stock) says these can differ, but no user is asking yet |
| Mainline 6.3 / 6.4 | Only to name the floor boundary exactly; no distro ships them |
| Kernels newer than the workstation's 7.0 | Regression-catching for future verifier changes |
| 32-bit / ia32 target | Belongs to W7, which changes the uprobe path; the matrix gains an architecture axis then, not before |

## 5. What each cell runs

Ordered by what it would have caught. The first two rows are the ones that
matter; the rest is cheap to add once a VM is up.

| Command | Catches | Exists? |
| --- | --- | --- |
| `scripts/verify-attach-e2e.sh` | All three defects. This is the only lane that loads programs *and* attaches *and* watches a target exit. | yes |
| `p11scope profile --pid <target> --duration N` against a short-lived target | The leader-exit loss; a 30-second smoke test when the full lane is too slow | ad hoc, worth scripting |
| `scripts/verify-inspect-doctor.sh` | Whether `doctor` reports the environment correctly — the thing a user hits first on an unsupported kernel | yes |
| `scripts/verify-capability-tier.sh` | Tier classification per environment (T0–T4, `src/doctor.rs:34`) | yes |
| `scripts/verify-induced-gaps.sh` | Freeze/permission behaviour while attached | yes |
| the ~20 `--self-test` oracles | Nothing kernel-specific; they are already run by hosted CI and add nothing per cell | yes |

The self-tests are deliberately **not** part of a matrix cell: they validate
scripts against their own constants and are kernel-independent, so running them
per cell buys nothing but time.

`scripts/matrix/` today is about *container and orchestration* topology (docker,
kind, knative, fork scope, shared layers), not kernel versions. The kernel
matrix is a second axis, not a replacement, and the two multiply — a container
cell on an old kernel is a different test from either alone.

## 6. How to run one, verified today

This is the procedure that found the floor regression; it is written down
because the cost is the whole argument for having a matrix at all.

```sh
# 1. Fresh overlay off a held base (never boot the base itself)
qemu-img create -f qcow2 -F qcow2 \
  -b /home/user/src/m/p11scope-ws/vm-bases/jammy/jammy-server-cloudimg-amd64.img \
  /tmp/p11-vm/overlay.qcow2 20G

# 2. NoCloud seed over HTTP; no ISO tooling needed, and none is installed
python3 -m http.server 18191 --bind 127.0.0.1 --directory /tmp/p11-vm &

# 3. Boot with KVM. The old TCG constraint is gone: /dev/kvm is present and
#    the user is in the kvm group, so boot-to-SSH is about 20 seconds.
qemu-system-x86_64 -accel kvm -cpu host -machine q35 -m 2048 -smp 4 \
  -drive file=/tmp/p11-vm/overlay.qcow2,if=virtio,format=qcow2 \
  -netdev user,id=n1,hostfwd=tcp:127.0.0.1:2251-:22 -device virtio-net-pci,netdev=n1 \
  -smbios 'type=1,serial=ds=nocloud;s=http://10.0.2.2:18191/' \
  -display none -serial file:/tmp/p11-vm/serial.log -daemonize -pidfile /tmp/p11-vm/qemu.pid
```

Then `scp` the release binary in and run. Three facts make this work and are
worth keeping written down:

- **The binary is portable across these guests.** It needs at most `GLIBC_2.34`
  (`objdump -T`), and jammy ships 2.35 — so one host build runs on every cell,
  and no guest needs a Rust toolchain. If a future change raises the glibc
  requirement above 2.35, this whole method breaks and the matrix silently
  narrows to the build host's distro.
- **Kernels are apt packages.** A single jammy guest reached 5.15, 6.2, 6.5 and
  6.8 via `apt install linux-image-<ver>-generic` plus `grub-reboot`, and a noble
  guest reached the runner's exact `6.17.0-1022-azure`. One VM covers a column.
- **`grub-reboot` needs the full submenu path**, e.g.
  `gnulinux-advanced-<uuid>>gnulinux-5.15.0-187-generic-advanced-<uuid>`. The
  short form silently does nothing and the guest comes back on the newest
  kernel, which reads exactly like a passing test on the kernel you meant to
  boot.

The output directory must not have a world- or user-writable ancestor: p11scope
refuses `/tmp/...` and `/home/user/src/...` with `output directory ancestor ...
is untrusted: writable`. Write evidence to a root-owned path inside the guest.

## 7. What this document does not establish

- The exact floor between 6.2 and 6.5, and whether the 5.15 regression has one
  cause or several. Only `interface_return` was observed failing; programs load
  alphabetically, so later ones were never reached and may fail too.
- Any behaviour under lockdown `integrity`/`confidentiality`, cgroup v1, musl,
  or non-x86-64. All listed above, none measured.
- Whether backported vendor kernels (RHEL 5.14, Amazon 6.1) behave like their
  version number suggests. They are in SHOULD precisely because they might not.
- Runtime correctness beyond "attached and captured". A cell that attaches can
  still produce wrong evidence; `scripts/verify-attach-e2e.sh` checks that, the
  30-second smoke test does not.
