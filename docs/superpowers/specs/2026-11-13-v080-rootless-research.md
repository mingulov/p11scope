<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# v0.8.0 research: rootless Docker/Podman

**Verdict: yes, with a BPF token plus a one-shot host setup per container —
capture works, but host-process visibility stays unavailable, so the
v0.8.0 scope is attach-by-path capture of known provider files, not
host discovery.** Measured 2026-11-13 on Ubuntu 26.04, kernel
7.0.0-43-generic, Docker 29.8.1, runc 1.5.1, release image
`ghcr.io/mingulov/p11scope:0.7.0`. **Round 2 (same day, same kernel):
confirmed** — kryprobe's `EOPNOTSUPP` is the init-userns refusal, and
the correct split flow passes 5000/5000 probe hits from outer-nobody
at `unprivileged_bpf_disabled=2` (details below).

## What works today (rootless, no setup): nothing captures

A rootless OCI container (own userns, host pidns, like `docker run
--pid=host` rootless) runs the 0.7.0 image but captures nothing:

- `doctor -v`: `capture unavailable`; `BPF map create FAIL …
  Operation not permitted (os error 1)`; `uprobe-multi attach`
  refused; `cgroup version FAIL` (private cgroupns hides the unified
  hierarchy). PID namespace row confirms host PIDs are visible.
- `inventory --pid <host sleeper>`: falls back to the scan lane, then
  `cannot identify process mount namespace: Permission denied (os
  error 13)`; `0 callers`, coverage `partial`, 2 gaps. Honest unknown,
  no crash (exit 1).
- Same result for a target in the *same* userns: p11scope sheds all
  capabilities after setup (`capset … effective=0`, traced), and the
  commoncap LSM then denies even same-userns `ptrace_may_access`
  (`security/commoncap.c:cap_ptrace_access_check` requires
  `child.permitted ⊆ caller.effective`; `man 2 ptrace` §5.2, which
  applies to `PTRACE_MODE_READ` too).

Rootless Docker itself could not start here: `dockerd-rootless.sh`
needs `newuidmap` (`uidmap` package, not installed — not installed
per task rules) and refuses `--net=host` while no
slirp4netns/pasta/vpnkit binary exists. Rootlesskit fails with
`newuidmap … executable file not found`. Equivalent rootless OCI
containers were therefore built directly with runc (single-id
`0→1000` mapping, host pidns, host `/proc` bind — the same fixup
Docker's rootless specconv applies for `--pid=host`).

## Process visibility: the hard boundary

`cap_ptrace_access_check` (`security/commoncap.c`, `man 2 ptrace`
§5.2) denies whenever observer and target are in **different**
user namespaces unless the observer holds `CAP_SYS_PTRACE` in the
*target's* userns — for `READ` as well as `ATTACH`. Measured from a
rootless container at same uid: `/proc/<pid>/maps`, `/mem`,
`/environ`, `/ns/*` (follow), `/root/*` → `EACCES`; `cmdline`,
`stat`, `status`, `/sys/kernel/btf/vmlinux` → readable (no
`ptrace_may_access` gate). Consequences:

- A rootless container **cannot** read host processes' maps/mem,
  even same-user (Firefox/Chrome/ssh-agent): host discovery and
  caller attribution are impossible from any container userns.
- `/proc/<pid>/map_files` open additionally needs init-ns
  `CAP_CHECKPOINT_RESTORE` (`fs/proc/base.c:
  proc_map_files_get_link` uses
  `checkpoint_restore_ns_capable(&init_user_ns)`); readlink works,
  open fails `EPERM`. Not delegable, not covered by any token.
- `/proc/<pid>/mem` needs `PTRACE_MODE_ATTACH`, further gated by
  Yama: at scope 1 (Ubuntu default) non-descendant same-user attach
  fails (`security/yama/yama_lsm.c`), independent of namespaces.
- `--pid=host` is allowed rootless (runc proven locally, rootless
  Podman proven on fedora-sm1 in round 2 — host PIDs visible, maps
  still `EACCES`). Without it, host PIDs are invisible and only
  in-container targets exist.
- Cgroup paths of host processes are hidden by the container's
  cgroupns; `--cgroup` scope cannot address host cgroups rootless.

### Round 2: rootless engines on Fedora (executed on fedora-sm1)

fedora-sm1 (Fedora 44, kernel 7.2.15-200, podman 5.8.9, docker
29.9.2, `unprivileged_bpf_disabled=2`, SELinux) — one short
unprivileged session after the capture windows, fully cleaned
(6.5G free, no images/containers/daemons left):

- Rootless Podman `--pid=host` works: host PID 1 (`systemd`)
  visible via `cmdline`; container userns `0→1000` +
  `1→524288/65536`; `/proc/1/maps` → `EACCES`, confirming the
  cross-userns boundary on a real engine.
- `--cap-add BPF --cap-add PERFMON` works rootless: `CapEff`
  gains bits 38+39. Setup step 1 (container userns holding both
  caps) runs on Podman today; the only remaining gap is the
  privileged per-container bpffs delegation.
- Rootless Docker does **not** start there: `overlay is not
  supported for Rootless with SELinux` (overlay2; pasta present,
  slirp4netns absent). Host-specific, not fundamental —
  non-SELinux hosts don't hit it.
- Kernel 7.2 carries the same token UAPI (`BPF_TOKEN_CREATE`,
  vmlinux BTF present); no privileged token test was run there
  (out of scope on the shared host).

## BPF token: the working path (proven end to end)

Token mechanics (Linux 6.9+, all verified in kernel source):

- `delegate_cmds/maps/progs/attachs` bpffs options and mounting an
  sb owned by a non-init userns both require init-ns `CAP_SYS_ADMIN`
  (`kernel/bpf/inode.c`); `BPF_TOKEN_CREATE` requires current userns
  == sb userns ≠ init plus `CAP_BPF` in it (`kernel/bpf/token.c`).
- With a token, `PROG_LOAD`/`MAP_CREATE`/`BTF_LOAD` check
  `bpf_token_capable` (userns-scoped) instead of `capable()`
  (`kernel/bpf/syscall.c`); tracing program types (`KPROBE`,
  `RAW_TRACEPOINT`, `TRACING`, …) additionally need token
  `CAP_PERFMON`. `BPF_LINK_CREATE` takes **no** token: attach
  authority derives from the prog fd, and `uprobe_multi` attach
  performs no further capability/ptrace checks
  (`kernel/trace/bpf_trace.c:bpf_uprobe_multi_link_attach`,
  `link_create` in `syscall.c`).
- `capable()` from any non-init userns is unconditionally false
  (`security/commoncap.c:cap_capable_helper` level rule), so the
  delegated mount **cannot** be done post-hoc with plain `mount(2)`
  from inside the userns (measured `EPERM` for root, setuid-root
  and setcap helpers alike). The working split, taken from
  `tools/testing/selftests/bpf/prog_tests/token.c`, is:
  unprivileged `fsopen("bpf")` inside the userns, pass the fs fd
  out, privileged `fsconfig` (delegations) + `CREATE`, then
  `fsmount` + `move_mount` back inside.

Prototype (throwaway C under `/var/tmp`, since removed): container
`fsopen` + host-root `pidfd_getfd`/`fsconfig`/`CREATE` helper, then
raw `BPF_TOKEN_CREATE`/`MAP_CREATE`/`PROG_LOAD`/`LINK_CREATE`
(`BPF_F_TOKEN_FD` flag required on each command) attaching a
pid-filtered `uprobe_multi` to a same-user host process:
**2597 probe hits in 3 s, all calls succeed, from an unprivileged
container.**

What p11scope needs is fully delegable: program types
`kprobe` (uprobes/uretprobes/multi), `raw_tracepoint`
(`sched_process_exec/exit`), `tracing` (tp_btf `task_newtask`);
attach `trace_uprobe_multi` (+`perf_event` only for the singles
fallback, see below); map types `array`, `hash`, `prog_array`,
`ringbuf`, `percpu_array`, `percpu_hash` (+`cgroup_array`,
harmless to include); commands `map_create`, `prog_load`,
`btf_load` (aya loads vmlinux BTF via `BPF_BTF_LOAD`). The
`--attach-backend singles` fallback is **impossible** rootless:
`perf_event_open` for tracepoint/uprobe events needs init-ns
`CAP_PERFMON` at `paranoid ≥ 0` (`kernel/events/core.c:
perf_allow_tracepoint`; host runs paranoid 4) and takes no token.

Loader gap: p11scope uses **aya 0.14.0** (pinned + patched;
`Cargo.toml`), which has **no** token support (verified absent in
0.14.0 sources; upstream PR
[aya-rs/aya#1515](https://github.com/aya-rs/aya/pull/1515) is still
open). libbpf ≥ 1.5 already supports tokens
(`bpf_object_open_opts.bpf_token_path`,
`LIBBPF_BPF_TOKEN_PATH`). Token-aware loaders must also set
`expected_attach_type` at `PROG_LOAD`, not only at link time (round 2:
with attach 0 the kernel drops the token at load,
`syscall.c:2934-2938`, and the load fails `EPERM` even though
link-create would succeed). No OCI runtime wires delegation natively
(runc/crun/rootlesskit: none found); only LXD
(`security.delegate_bpf`) does. Ubuntu 23.10+ additionally confines
raw `unshare` to the `unprivileged_userns` AppArmor profile (own
uid_map write fails `EPERM`); runc/rootlesskit/Podman ship
`flags=(unconfined)` profiles and are unaffected.

### Round 2: kryprobe's `EOPNOTSUPP`, reconciled (exact 7.0 source)

kryprobe's `pins.md` note (2026-09-17, T12 era) — `BPF_TOKEN_CREATE`
→ errno 95 on every bpffs instance, sysctl 2 and 0 — predates its
own T17 child-userns split flow (`token/userns.rs`, which is the
correct setup). Against Ubuntu `linux-source-7.0.0-43.43`
(`kernel/bpf/token.c:bpf_token_create`):

- The **sole** `EOPNOTSUPP` site is `token.c:149-151`:
  `current_user_ns() == &init_user_ns`. Two `EPERM` gates precede
  it (minter userns == bpffs `s_user_ns`, `token.c:144-145`;
  `CAP_BPF` in it, `:146-147`), so root in the init ns passes
  both and always lands on 95 — on every instance, as observed.
  The sysctl is never consulted by token-create, so the 2-vs-0
  variation was immaterial; and token *use* explicitly bypasses
  the sysctl (`syscall.c:1460` map, `:2957` prog), so tokens work
  at this host's `unprivileged_bpf_disabled=2`.
- No-delegation is a different errno: `ENOENT` (`token.c:154-158`),
  reachable only when userns+caps already match (a non-init minter
  on the system bpffs gets `EPERM`, not `ENOENT`). There is no
  token kconfig gate (part of `CONFIG_BPF_SYSCALL`), and the LSM
  hook (`security_bpf_token_create`, `token.c:188`) is
  default-allow — zero BPF-LSM programs here, AppArmor mediates no
  token hook.
- Privileged steps confirmed at exact lines: non-empty
  `delegate_*` needs init-ns `CAP_SYS_ADMIN` (`inode.c:924-925`),
  as does `CREATE` of an fs-context opened in a non-init userns
  (`inode.c:1014-1015`, via `bpf_fill_super`).

Re-run 2026-11-13 (throwaway C, since removed; privileged half under
the local lock): negative control as root in the init ns
(userns 4026531837) on `/sys/fs/bpf` → `EOPNOTSUPP`, reproducing
kryprobe; positive split flow (child userns, `uid_map 0 65534 1`,
host-root `fsconfig`+`CREATE`, in-userns token create) →
token/map/prog/link all `OK` from outer-nobody and **5000/5000
probe hits** on a same-file target (offset cross-checked via
tracefs). Tokens can work on this kernel; the required setup is
exactly the four-step host procedure below, with the minter outside
the init userns.

## Scan-only without BPF

Without a token, only targets in the **same** userns whose
permitted caps ⊆ observer's post-shed effective set are scannable
— i.e. unprivileged siblings, and container runtimes grant targets
caps (runc default `KILL,NET_BIND_SERVICE,AUDIT_WRITE`) that break
even that. Host targets: no maps, no mem, no ns identity, no
map_files — scan reports `PARTIAL` with named gaps, as measured.
There is no scan-only host story for v0.8.0.

## Impossible, plainly

- **Docker Desktop / VM engines**: containers run inside a Linux
  VM; `--pid=host` reaches the VM's processes, never the laptop's
  ([Docker Docs: Platform FAQs](https://docs.docker.com/faqs/platform/)).
  Host observation is architecturally impossible.
- Cross-userns `ptrace_may_access` (commoncap), `map_files`
  (init `CAP_CHECKPOINT_RESTORE`), `perf_event_open` singles
  (init `CAP_PERFMON`), plain post-hoc delegated bpffs mount
  (`capable()` level rule), plain bpffs/any mount setup without a
  privileged per-container step.

## Exact host setup (per rootless container)

1. Start the container rootless with host pidns, container userns
   holding `CAP_BPF`+`CAP_PERFMON` (grantable unprivileged within
   the userns; Docker: `--cap-add BPF --cap-add PERFMON`), the
   provider files bind-mounted at identical paths, and `/proc`
   from the host.
2. Inside (entrypoint wrapper or `runc exec`): `fsopen("bpf")`,
   hold the fd (fixed number or SCM_RIGHTS to the helper).
3. On the host, one shot per container (root, or a setcap'd
   helper — file caps suffice since it never enters the userns):
   obtain the fs fd (`pidfd_getfd`/socket), `fsconfig` the four
   `delegate_*` sets above, `FSCONFIG_CMD_CREATE`.
4. Inside: `fsmount` + `move_mount` to `/sys/fs/bpf`; observer
   creates the token and loads/attaches with `BPF_F_TOKEN_FD`.

## Recommended v0.8.0 scope

**Rootless attach-by-path capture** (no host discovery): operator
names provider files; observer resolves symbol file-offsets from
ELF, attaches system-wide or pid-filtered `uprobe_multi` via
token, attributes events by pid/comm from `stat`/`cmdline`;
maps/mem/map_files/caller proof stay `unknown` with named gaps.

- Effort (agent hours): aya token plumbing
  (`BPF_TOKEN_CREATE`, `token_fd`+`BPF_F_TOKEN_FD` on
  map/prog/BTF creates, bpffs-path option; extend the vendored
  patch stack or track upstream #1515) 20–30; attach-by-path
  session + ELF offset resolution + gap taxonomy 15–20; host
  setup helper + docs 8–12; cells below 10–15. Total ≈ 55–75.
- Not in scope: singles backend, `--system` discovery,
  map_files identity, Docker Desktop, full p11scope-in-Podman E2E
  (Podman engine mechanics executed on sm1 in round 2; E2E waits
  for the token-aware build).
- Test plan cells: (1) `rootless-token-attach`: scratch
  container + helper asserts token load/attach + N>0 hits on a
  ledgered workload; (2) `rootless-refusals`: no-token run
  asserts `EPERM` at `MAP_CREATE` + `PARTIAL` gaps, never
  silent zero; (3) `rootless-visibility`: matrix of
  maps/mem/map_files/cmdline/stat per same-/cross-userns;
  (4) `bpf-kernels` token shard on 6.9/6.12/latest;
  (5) AppArmor `unprivileged_userns` regression (raw unshare
  still crippled, runtime path unaffected).

## Sources

Kernel: `kernel/bpf/{token,syscall,inode}.c`,
`kernel/trace/bpf_trace.c`, `kernel/events/core.c`,
`security/{commoncap,yama}/…`, `fs/{proc/base,namespace,
fsopen,fs_context}.c`, `tools/testing/selftests/bpf/
prog_tests/token.c`, `Documentation` via
[kernel.org](https://docs.kernel.org/userspace-api/ebpf/syscall.html).
Man pages: `bpf(2)`, `ptrace(2)` §5.2, `capabilities(7)`,
`user_namespaces(7)`. Lore: BPF-token series (`bpf-next`,
Andrii Nakryiko, Jan 2024). Engines: Docker rootlesskit,
Podman/Red Hat `--pid=host` docs, LXD `security.delegate_bpf`,
[Docker Desktop](https://docs.docker.com/faqs/platform/).
Loaders: libbpf 1.5 changelog, aya 0.14.0 sources,
[aya#1515](https://github.com/aya-rs/aya/pull/1515).
