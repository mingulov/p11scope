/* SPDX-License-Identifier: GPL-2.0-only */
/* Reproducible UAPI assertion check for the identity raw syscalls (F6).
 * Compiled with `-fsyntax-only` against the HOST <linux/bpf.h> at build
 * time: every `_Static_assert` below must hold or the build fails. This
 * pins the command numbers, attach type, map types/flags, and the struct
 * layouts `src/attach/identity_iter.rs` mirrors — independently of the
 * aya-bindings cross-check in the test harness (which covers the values
 * plus the layouts bindgen exposes as plain structs).
 *
 * Layout notes: `link_create.iter_info`/`iter_info_len` only exist on
 * headers new enough for task iterators (5.12+); older headers fail this
 * check loudly at build time instead of mis-linking at runtime.
 */
#include <linux/bpf.h>
#include <stddef.h>

/* Command numbers. */
_Static_assert(BPF_MAP_CREATE == 0, "map create cmd");
_Static_assert(BPF_MAP_UPDATE_ELEM == 2, "map update cmd");
_Static_assert(BPF_MAP_DELETE_ELEM == 3, "map delete cmd");
_Static_assert(BPF_OBJ_GET_INFO_BY_FD == 15, "obj info cmd");
_Static_assert(BPF_LINK_CREATE == 28, "link create cmd");
_Static_assert(BPF_ITER_CREATE == 33, "iter create cmd");

/* Attach type, map types, map flags. */
_Static_assert(BPF_TRACE_ITER == 28, "trace iter attach");
_Static_assert(BPF_MAP_TYPE_HASH == 1, "hash type");
_Static_assert(BPF_MAP_TYPE_ARRAY == 2, "array type");
_Static_assert(BPF_F_WRONLY == 16, "wronly flag");
_Static_assert(BPF_F_MMAPABLE == 1024, "mmapable flag");

/* `union bpf_iter_link_info` task member: `{tid@0,pid@4,pid_fd@8}`. */
_Static_assert(sizeof(union bpf_iter_link_info) == 16, "iter link info size");
_Static_assert(__builtin_offsetof(union bpf_iter_link_info, task.tid) == 0, "task tid");
_Static_assert(__builtin_offsetof(union bpf_iter_link_info, task.pid) == 4, "task pid");
_Static_assert(__builtin_offsetof(union bpf_iter_link_info, task.pid_fd) == 8, "task pid_fd");

/* `BPF_LINK_CREATE` attr prefix through `iter_info_len`. */
_Static_assert(__builtin_offsetof(union bpf_attr, link_create.prog_fd) == 0, "link prog");
_Static_assert(__builtin_offsetof(union bpf_attr, link_create.target_fd) == 4, "link target");
_Static_assert(__builtin_offsetof(union bpf_attr, link_create.attach_type) == 8, "link attach");
_Static_assert(__builtin_offsetof(union bpf_attr, link_create.flags) == 12, "link flags");
_Static_assert(__builtin_offsetof(union bpf_attr, link_create.iter_info) == 16, "link iter info");
_Static_assert(__builtin_offsetof(union bpf_attr, link_create.iter_info_len) == 24, "link iter len");

/* `BPF_ITER_CREATE` attr: `{link_fd@0, flags@4}`, 8 bytes. */
_Static_assert(sizeof(((union bpf_attr *)0)->iter_create) == 8, "iter create size");
_Static_assert(__builtin_offsetof(union bpf_attr, iter_create.link_fd) == 0, "iter link");
_Static_assert(__builtin_offsetof(union bpf_attr, iter_create.flags) == 4, "iter flags");

/* `BPF_MAP_*_ELEM` attr: `{map_fd@0,key@8,value@16,flags@24}`, 32 bytes. */
_Static_assert(__builtin_offsetof(union bpf_attr, map_fd) == 0, "elem map fd");
_Static_assert(__builtin_offsetof(union bpf_attr, key) == 8, "elem key");
_Static_assert(__builtin_offsetof(union bpf_attr, value) == 16, "elem value");
_Static_assert(__builtin_offsetof(union bpf_attr, flags) == 24, "elem flags");

/* `BPF_OBJ_GET_INFO_BY_FD` attr: `{bpf_fd@0,info_len@4,info@8}`, 16 bytes. */
_Static_assert(sizeof(((union bpf_attr *)0)->info) == 16, "obj info size");
_Static_assert(__builtin_offsetof(union bpf_attr, info.bpf_fd) == 0, "obj info fd");
_Static_assert(__builtin_offsetof(union bpf_attr, info.info_len) == 4, "obj info len");
_Static_assert(__builtin_offsetof(union bpf_attr, info.info) == 8, "obj info ptr");

/* `struct bpf_map_info` prefix read by handle validation. */
_Static_assert(__builtin_offsetof(struct bpf_map_info, type) == 0, "map info type");
_Static_assert(__builtin_offsetof(struct bpf_map_info, key_size) == 8, "map info key");
_Static_assert(__builtin_offsetof(struct bpf_map_info, value_size) == 12, "map info value");
_Static_assert(__builtin_offsetof(struct bpf_map_info, max_entries) == 16, "map info max");
_Static_assert(__builtin_offsetof(struct bpf_map_info, map_flags) == 20, "map info flags");
