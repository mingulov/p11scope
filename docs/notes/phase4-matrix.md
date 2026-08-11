# Phase 4 environment matrix — results

Ground truth for every row: `spike/harness.c`, oracle `spike/expected.txt`
(the same 9-function-call oracle `verify-attach-e2e.sh` uses). Host:
Ubuntu 24.04.4, glibc 2.39, kernel 7.0.0-28-generic, Docker 29.7.2
(storage driver `overlay2`, cgroup driver `systemd`, cgroup2 unified
hierarchy).

| Environment | Script | Result | Completeness | Measured privileges |
| --- | --- | --- | --- | --- |
| Docker, single container | `scripts/matrix/verify-docker.sh` | PASS — exact counts, positive isolation via discover-in-container + `/proc/<pid>/root` prefix | COMPLETE (136/136 probes) | Unprivileged `p11scope profile`: exit 1, `... cannot identify the file now (read failed: Permission denied (os error 13))` reading `/proc/<pid>/root/...`, refuses to attach. `docker exec` discovery step needs no host root (works as the `docker` group member that ran it). Minimum working set: root (via `sudo`) for `p11scope profile`; no special privilege for `p11scope-discover` run inside the container. |

## Row 1: Docker container capture (Task 2)

Two problems, both solved explicitly in `verify-docker.sh`:

1. **Provider path inside the container is not the host path.**
   `p11scope-discover` has no `--pid` flag (checked
   `crates/discover/src/main.rs`: only `--module`/`-o`/`--help`) — the
   brief's "designed for this" reading doesn't match the current CLI. So
   this row runs the helper **inside** the container via `docker exec`
   (bind-mounted in from the host build — this host is Ubuntu 24.04/glibc
   2.39, the same as the `ubuntu:24.04` image, so the host-built dynamic
   binary runs unmodified, no cross-container build needed) and copies the
   resulting manifest out. The manifest's object paths come out
   container-relative (SoftHSM2 resolves through a symlink to
   `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`); the script then
   rewrites every object path with a `/proc/<container-pid>/root/` prefix
   before handing the manifest to `p11scope profile`. This one rewrite
   feeds two separate consumers that both read `manifest.objects[].path`
   directly with no namespace awareness of their own: `attach.rs`'s
   `prog.attach(point, &slot.object, ...)` (the actual uprobe target) and
   `verify.rs::check_reuse` (the identity re-check gate). Matches the
   Phase 0 spike's bpftrace path-prefix trick exactly (see
   `docs/superpowers/plans/2026-08-10-phase0-feasibility-spike.md`, Task
   4).
2. **Scope by the container's cgroup.** `--cgroup /sys/fs/cgroup$(sed
   's/^0:://' /proc/<pid>/cgroup)` — the container's own leaf cgroup, using
   Task 1's descendant matching so this is correct whether or not the
   workload runs in a nested sub-cgroup.

Exact call counts matched `spike/expected.txt` on every function;
`evidence.completeness == "COMPLETE"`, `attached_probes == 136` (68 slots
x2 uprobe+uretprobe).

## Not yet covered by this file

Shared-image-layer, Kubernetes/kind, and Knative rows (later Phase 4
tasks) are not run here.
