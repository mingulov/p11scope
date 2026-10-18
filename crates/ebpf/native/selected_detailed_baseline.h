/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_SELECTED_BASELINE_H
#define P11SCOPE_SELECTED_BASELINE_H
#include "image_identity.h"
#define BASELINE_QUERY_LIMIT 1024U
#define BASELINE_VISIT_LIMIT 65536ULL
struct baseline_request { u64 generation; u32 tgid; u32 slot; };
struct baseline_control {
    u64 generation; u64 deadline_ns; u64 visit_limit; u64 count;
    u64 visits; u64 emitted; u64 failed;
};
struct baseline_row {
    u64 generation; u64 cookie; u64 exec_id; u64 visits;
    u32 slot; u32 status;
};
_Static_assert(sizeof(struct baseline_request) == 16, "baseline request ABI");
_Static_assert(sizeof(struct baseline_control) == 56, "baseline control ABI");
_Static_assert(sizeof(struct baseline_row) == 40, "baseline row ABI");
#endif
