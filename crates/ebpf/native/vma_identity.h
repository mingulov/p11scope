/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_VMA_IDENTITY_H
#define P11SCOPE_VMA_IDENTITY_H

/* Stage 3 Wave D kernel-side identity (D2a): per-range proof primitive.
 * Two `iter/task_vma` programs compare `vm_file->f_inode` pointers in the
 * kernel against per-pass anchor slots. The Rust side mirrors every ABI
 * constant in `src/attach/identity_iter.rs`, which pins the shared layout
 * with size/offset assertions; update both together or not at all. */

typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned short u16;
typedef unsigned char u8;
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name

/* Map types and flags (`linux/bpf.h`; stable UAPI, no CO-RE). */
#define P11_IDENT_MAP_HASH 1
#define P11_IDENT_MAP_ARRAY 2
#define P11_IDENT_F_WRONLY 16
#define P11_IDENT_F_MMAPABLE 1024
#define P11_IDENT_UPDATE_ANY 0

/* `VM_EXEC` (`linux/mm.h`); maps `x` is exactly this bit (F0). */
#define P11_IDENT_VM_EXEC 4UL

/* One slot per anchored object (§3.2); examined objects join up to their cap. */
#define P11_IDENT_ANCHOR_SLOTS 1024
/* Slot arena stride: an anchor page plus its guard page (§3.3). */
#define P11_IDENT_ANCHOR_STRIDE 8192UL
#define P11_IDENT_PAGE 4096UL
/* `scope_bitmap` words: 65,536 `u64`s cover `PID_MAX_LIMIT` (2^22). */
#define P11_IDENT_SCOPE_WORDS 65536

/* Record ABI (§5): one 32-byte little-endian layout for every record. */
#define P11_IDENT_MAGIC 0x4950
#define P11_IDENT_VERSION 1
#define P11_IDENT_RECORD_LEN 32
#define P11_IDENT_KIND_VMA 1
#define P11_IDENT_KIND_ANCHOR 2
#define P11_IDENT_KIND_END 3
#define P11_IDENT_NONE 0xFFFFFFFFU
#define P11_IDENT_ANCHOR_OK 0
#define P11_IDENT_ANCHOR_DUP 1
#define P11_IDENT_ANCHOR_FULL 2
#define P11_IDENT_ANCHOR_BAD_SHAPE 3

struct p11_vma_identity_record {
    u16 magic;
    u8 version;
    u8 kind;
    u32 a;
    u64 start;
    u64 end;
    u32 verdict;
    u32 gen;
};

_Static_assert(sizeof(struct p11_vma_identity_record) == 32, "record ABI");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, magic) == 0, "magic");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, version) == 2, "version");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, kind) == 3, "kind");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, a) == 4, "a");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, start) == 8, "start");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, end) == 16, "end");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, verdict) == 24, "verdict");
_Static_assert(__builtin_offsetof(struct p11_vma_identity_record, gen) == 28, "gen");

/* `anchors` value: the installed slot plus its pass generation (I2). */
struct p11_anchor_entry {
    u32 slot;
    u32 pad;
    u64 gen;
};
_Static_assert(sizeof(struct p11_anchor_entry) == 16, "anchor entry ABI");
_Static_assert(__builtin_offsetof(struct p11_anchor_entry, slot) == 0, "slot");
_Static_assert(__builtin_offsetof(struct p11_anchor_entry, gen) == 8, "entry gen");

/* `config[0]`: observer addresses and counters only, never kernel pointers. */
struct p11_identity_config {
    u64 gen;
    u64 arena_base;
    u64 arena_len;
    u32 slots;
    u32 pad;
};
_Static_assert(sizeof(struct p11_identity_config) == 32, "config ABI");
_Static_assert(__builtin_offsetof(struct p11_identity_config, gen) == 0, "config gen");
_Static_assert(__builtin_offsetof(struct p11_identity_config, arena_base) == 8, "arena base");
_Static_assert(__builtin_offsetof(struct p11_identity_config, arena_len) == 16, "arena len");
_Static_assert(__builtin_offsetof(struct p11_identity_config, slots) == 24, "slots");

/* Stable iterator context: fixed kernel offsets, never CO-RE. */
struct p11_iter_meta {
    void *seq;
    u64 session_id;
    u64 seq_num;
};
struct p11_iter_task_vma {
    struct p11_iter_meta *meta;
    struct task_struct *task;
    struct vm_area_struct *vma;
};

/* Minimal CO-RE shapes: field names, never fixed target offsets. */
struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));
struct inode;
struct file {
    struct inode *f_inode;
} __attribute__((preserve_access_index));
struct vm_area_struct {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    struct file *vm_file;
} __attribute__((preserve_access_index));

/* `BPF_CORE_FIELD_EXISTS` for `__builtin_preserve_field_info` (verified
 * against the emitted `.BTF.ext`: the guard lowers to a kind-2 relo). */
#define P11_IDENT_FIELD_EXISTS 2
#define p11_field_exists(field) __builtin_preserve_field_info(field, P11_IDENT_FIELD_EXISTS)
#define P11_READ(dst, src) \
    p11_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

static void *(*p11_map_lookup)(void *map, const void *key) = (void *)1;
static long (*p11_map_update)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*p11_map_delete)(void *map, const void *key) = (void *)3;
static long (*p11_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static long (*p11_seq_write)(void *seq, const void *data, u32 len) = (void *)127;
#endif
