/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_SELECTED_DETAILED_H
#define P11SCOPE_SELECTED_DETAILED_H
#include "image_identity.h"
#define SELECTED_ORDINARY 0U
#define SELECTED_MODE 1U
#define SELECTED_CLOSED 1ULL
#define SELECTED_ACTIVE 2ULL
#define SELECTED_TERMINAL 3ULL
#define SELECTED_PARENT_CGROUP 2ULL
#define SELECTED_VISIT_LIMIT 65536ULL
struct selected_target {
    u32 mode;
    u32 tgid;
    u64 cookie;
    u64 exec_id;
    u64 parent_kind;
};
struct selected_bootstrap_control {
    u64 generation;
    u64 deadline_ns;
    u64 visit_limit;
    u64 visits;
    u64 emitted;
    u64 failed;
};
struct selected_bootstrap_row {
    u64 generation;
    u64 cookie;
    u64 exec_id;
    u64 visits;
    u32 tgid;
    u32 status; /* 1 identity, 2 END */
};
_Static_assert(sizeof(struct selected_target) == 32, "selected target ABI");
_Static_assert(__builtin_offsetof(struct selected_target, cookie) == 8, "selected cookie offset");
_Static_assert(sizeof(struct selected_bootstrap_control) == 48, "selected bootstrap control ABI");
_Static_assert(sizeof(struct selected_bootstrap_row) == 40, "selected bootstrap row ABI");
u32 p11_selected_current_allowed(u32 parent_allowed, u32 tgid);
u32 p11_selected_invalidate_tgid(u32 tgid);
#endif
