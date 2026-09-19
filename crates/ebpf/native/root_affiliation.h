/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_ROOT_AFFILIATION_H
#define P11SCOPE_ROOT_AFFILIATION_H
typedef unsigned int u32;
typedef unsigned long long u64;
#define ROOT_SEC(name) __attribute__((section(name), used))
#define ROOT_INLINE inline __attribute__((always_inline))
#define ROOT_UINT(name, value) int (*name)[value]
#define ROOT_TYPE(name, value) typeof(value) *name
#define ROOT_AFFILIATION_LIMIT_NORMAL 16384ULL
#define ROOT_AFFILIATION_LIMIT_SMALL 3ULL
#ifdef P11SCOPE_SMALL_STATE_MAPS
#define ROOT_AFFILIATION_LIMIT ROOT_AFFILIATION_LIMIT_SMALL
#else
#define ROOT_AFFILIATION_LIMIT ROOT_AFFILIATION_LIMIT_NORMAL
#endif
#define ROOT_CLONE_THREAD 0x00010000ULL
#define ROOT_CAS_TRIES 8
#define ROOT_BAD_CONTROL 1ULL
#define ROOT_CAPACITY 2ULL
#define ROOT_RESERVE_CAS 4ULL
#define ROOT_CREATE_FAILED 8ULL
#define ROOT_EXISTING_CHILD 16ULL
#define ROOT_BAD_CELL 32ULL
#define ROOT_EXIT_CLASSIFIER 64ULL
#define ROOT_EXIT_DELETE 128ULL
#define ROOT_REFUND_FAILED 256ULL
enum root_propagation_status { ROOT_NOT_APPLICABLE, ROOT_PARENT_UNKNOWN, ROOT_INSTALLED, ROOT_FAILED };
struct task_struct;
struct root_affiliation_control {
    u64 affiliation_reserved;
    u64 failure_flags;
    u64 admission_failures;
    u64 create_failures;
    u64 malformed_failures;
    u64 classifier_failures;
    u64 delete_failures;
    u64 refund_failures;
};
_Static_assert(sizeof(struct root_affiliation_control) == 64, "root control ABI");
_Static_assert(_Alignof(struct root_affiliation_control) == 8, "root alignment");
#define ROOT_OFFSET(field, offset) _Static_assert(__builtin_offsetof(struct root_affiliation_control, field) == offset, "root offset")
ROOT_OFFSET(affiliation_reserved, 0);
ROOT_OFFSET(failure_flags, 8);
ROOT_OFFSET(admission_failures, 16);
ROOT_OFFSET(create_failures, 24);
ROOT_OFFSET(malformed_failures, 32);
ROOT_OFFSET(classifier_failures, 40);
ROOT_OFFSET(delete_failures, 48);
ROOT_OFFSET(refund_failures, 56);
static void *(*root_map_lookup)(void *, const void *) = (void *)1;
static u64 *(*root_storage_get)(void *, struct task_struct *, u64 *, u64) = (void *)156;
static long (*root_storage_delete)(void *, struct task_struct *) = (void *)157;
static struct task_struct *(*root_current_task)(void) = (void *)158;
#endif
