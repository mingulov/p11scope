# Slice 1b-1 spikes — measured /proc access (spec §6.4 unprivileged half, §6.6)

Host: 7.0.0-28-generic, glibc 2.39 (Ubuntu GLIBC 2.39-0ubuntu8.8), ptrace_scope=1,
perf_event_paranoid=4.

| Question | Answer | Evidence |
| --- | --- | --- |
| `/proc/<pid>/maps` for a same-uid non-descendant | readable | `tests/proc_access.rs::mem_access_for_a_same_uid_non_descendant_follows_the_documented_ptrace_rules` |
| `/proc/<pid>/mem` for the same target under `ptrace_scope=1` | refused | same test |
| `/proc/self/root/<path>` opens the mapped inode | yes | `tests/proc_access.rs::proc_root_path_opens_the_same_inode_the_mapping_names` |
| `mapping_file_key` resolves on this filesystem | yes, btrfs (`/home` is `/dev/sda1` btrfs) | same test |
| `mapping_file_key` agrees with the mapping device on overlay2 | no; Docker and kind expose the same inode through mount-specific anonymous devices, so identity is downgraded to inode-only `stat` evidence | 2026-08-17 `scripts/matrix/verify-docker.sh`, `scripts/matrix/verify-kind-pod.sh`; Task 14 report |

**Consequence for `scan_pid` (Task 6):** when `/proc/<pid>/mem` is refused the scan reports
`unavailable: ptrace` and the capture continues with whatever other source it has, per spec
§4.1 step 3 — it is never fatal.

The overlay result does not prove that equal inode metadata and bytes from two
overlay instances are one physical object. The shared-layer implementation
collapses the measured common case, publishes that uncertainty, and forces
`PARTIAL`; `scripts/matrix/verify-shared-layer.sh` then proves exact counts for
the concrete Docker instances.

## Privilege re-measurement (2026-08-17)

Task 14 reran `scripts/matrix/verify-fork-scope.sh` at
`kernel.perf_event_paranoid=4`, `kernel.yama.ptrace_scope=1`. `CAP_SYS_ADMIN`
was required for uprobe attach; `CAP_BPF`+`CAP_PERFMON` attached 0/136 probes.
For a same-UID non-descendant, manifest-free scanning additionally required
`CAP_SYS_PTRACE` (or a descendant target / changed ptrace policy):
`CAP_SYS_ADMIN` alone attached 136/136 from a manifest but planned 0 probes
manifest-free, while `CAP_SYS_ADMIN`+`CAP_SYS_PTRACE` scanned and attached
136/136. No new privileged experiment was run for the documentation task.
