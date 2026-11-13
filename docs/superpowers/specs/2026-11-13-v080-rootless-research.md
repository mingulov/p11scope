<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# v0.8.0 research: rootless Docker/Podman

**Verdict: yes, with a BPF token plus a one-shot host setup per container —
capture works, but host-process visibility stays unavailable, so the
v0.8.0 scope is attach-by-path capture of known provider files, not
host discovery.** Measured 2026-11-13 on Ubuntu 26.04, kernel
7.0.0-43-generic, Docker 29.8.1, runc 1.5.1, release image
`ghcr.io/mingulov/p11scope:0.7.0`.

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
- `--pid=host` is allowed rootless (runc proven here; rootless
  Podman likewise per Red Hat/Docker docs — Podman itself was not
  installed here, so Docker/Podman-daemon specifics are cited, not
  executed). Without it, host PIDs are invisible and only
  in-container targets exist.
- Cgroup paths of host processes are hidden by the container's
  cgroupns; `--cgroup` scope cannot address host cgroups rootless.

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
`LIBBPF_BPF_TOKEN_PATH`). No OCI runtime wires delegation natively
(runc/crun/rootlesskit: none found); only LXD
(`security.delegate_bpf`) does. Ubuntu 23.10+ additionally confines
raw `unshare` to the `unprivileged_userns` AppArmor profile (own
uid_map write fails `EPERM`); runc/rootlesskit/Podman ship
`flags=(unconfined)` profiles and are unaffected.

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
  map_files identity, Docker Desktop, daemonless Podman E2E
  (revisit when a Podman host is available).
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
