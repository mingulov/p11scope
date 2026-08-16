# Slice 1b-1 spikes — measured /proc access (spec §6.4 unprivileged half, §6.6)

Host: 7.0.0-28-generic, glibc 2.39 (Ubuntu GLIBC 2.39-0ubuntu8.8), ptrace_scope=1,
perf_event_paranoid=4.

| Question | Answer | Evidence |
| --- | --- | --- |
| `/proc/<pid>/maps` for a same-uid non-descendant | readable | `tests/proc_access.rs::maps_is_readable_and_mem_is_refused_for_a_same_uid_non_descendant` |
| `/proc/<pid>/mem` for the same target under `ptrace_scope=1` | refused | same test |
| `/proc/self/root/<path>` opens the mapped inode | yes | `tests/proc_access.rs::proc_root_path_opens_the_same_inode_the_mapping_names` |
| `mapping_file_key` resolves on this filesystem | yes, btrfs (`/home` is `/dev/sda1` btrfs) | same test |

**Consequence for `scan_pid` (Task 6):** when `/proc/<pid>/mem` is refused the scan reports
`unavailable: ptrace` and the capture continues with whatever other source it has, per spec
§4.1 step 3 — it is never fatal.

**Not answered here (root/docker-gated, spec §6.4 second half):** whether
`mapping_file_key` agrees with the mapping device on overlay2 and btrfs. Recorded UNRUN;
Task 14's docker lane answers it under owner approval.
