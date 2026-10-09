/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_IMAGE_IDENTITY_QUERY_H
#define P11SCOPE_IMAGE_IDENTITY_QUERY_H
typedef unsigned int u32;
typedef unsigned long long u64;
#define IMG_SEC(name) __attribute__((section(name), used))
#define IMG_INLINE inline __attribute__((always_inline))
#define IMG_UINT(name, value) int (*name)[value]
#define IMG_TYPE(name, value) typeof(value) *name
#define IMG_LIMIT 16384U
#define IMG_REQUEST_LIMIT 1024U
#define IMG_VISIT_LIMIT 65536ULL
#define IMG_CAS_TRIES 8
#define IMG_GEN_COVERAGE 3U
#define IMG_DISABLED 0ULL
#define IMG_ENABLED 1ULL
#define IMG_FAILED 2ULL
#define IMG_READY 1ULL
#define IMG_POISONED 2ULL
#define IMG_ROW_READY 1U
#define IMG_ROW_UNKNOWN 2U
#define IMG_ROW_END 3U
struct image_continuity { u64 seq; u64 exec_id; u64 state; };
struct image_query_request { u64 generation; u64 cookie; u64 slot; };
struct image_query_control {
    u64 generation; u64 deadline_ns; u64 visit_limit; u64 count;
    u64 visits; u64 emitted; u64 failed;
};
struct image_query_row {
    u64 generation; u64 cookie; u64 exec_id; u64 sequence;
    u32 slot; u32 status;
};
_Static_assert(sizeof(struct image_continuity) == 24, "image continuity ABI");
_Static_assert(sizeof(struct image_query_request) == 24, "image request ABI");
_Static_assert(sizeof(struct image_query_control) == 56, "image query control ABI");
_Static_assert(sizeof(struct image_query_row) == 40, "image row ABI");
u32 p11_image_entry(u64 tgid, u64 cookie, u64 exec_id);
#endif
