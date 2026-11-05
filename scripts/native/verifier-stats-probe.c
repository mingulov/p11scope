/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Qualification-only x86-64 preload probe. The product's actual loader owns
 * relocations, maps, flags, program types and lifetime. Only verifier logging
 * changes: one bounded STATS buffer on its original BPF_PROG_LOAD call.
 * Successful stats are needed on 5.15, before prog_info.verified_insns existed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#if !defined(__x86_64__) || SYS_bpf != 321
#error "This qualification probe requires the native Linux x86-64 syscall ABI"
#endif

#ifndef PROBE_FORWARD_ONLY
#define LOG_BYTES (1024U * 1024U)
#define BTF_BYTES (4U * 1024U * 1024U)
#define TOTAL_BTF_BYTES (16U * 1024U * 1024U)
#define BTF_SLOTS 16U
#define ATTR_BYTES 4096U
#define ROOT_BYTES 128U

static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { int fd; uint32_t id; unsigned char *bytes; size_t length; } btfs[BTF_SLOTS];
static size_t btf_total;
static _Atomic uint64_t emitted_rows;
static _Atomic uint64_t write_failures;
static pid_t probe_owner = -1;

__attribute__((constructor))
static void bind_observer(void)
{
    int saved = errno;
    const char *inherited = getenv("P11SCOPE_VERIFIER_STATS_OWNER_PID");
    if (!inherited && getenv("P11SCOPE_VERIFIER_STATS_FD")) {
        char owner[32];
        snprintf(owner, sizeof(owner), "%ld", (long)getpid());
        if (setenv("P11SCOPE_VERIFIER_STATS_OWNER_PID", owner, 0) == 0) probe_owner = getpid();
    } else if (inherited && *inherited) {
        char *end;
        errno = 0;
        long owner = strtol(inherited, &end, 10);
        if (!errno && !*end && owner > 0 && owner == getpid()) probe_owner = getpid();
    }
    errno = saved;
}

/* Do not read nonexistent C varargs. This is the same native register shuffle
 * as libc's syscall entry: arg6 remains the original caller's stack word.
 * Unknown calls enter the kernel with those exact original argument bits.
 * Only SYS_bpf tail-branches into the fixed (number,cmd,attr,size) C ABI.
 */
__asm__(
    ".text\n.globl syscall\n.type syscall,@function\nsyscall:\n"
    "cmpq $321,%rdi\nje p11scope_verifier_bpf\n"
    "movq %rdi,%rax\nmovq %rsi,%rdi\nmovq %rdx,%rsi\nmovq %rcx,%rdx\n"
    "movq %r8,%r10\nmovq %r9,%r8\nmovq 8(%rsp),%r9\nsyscall\n"
    "cmpq $-4095,%rax\njae 1f\nret\n"
    "1: negl %eax\nmovl %eax,%edi\njmp p11scope_verifier_errno\n"
    ".size syscall,.-syscall\n"
);

__attribute__((visibility("hidden")))
long p11scope_verifier_errno(int value)
{
    errno = value;
    return -1;
}

static long raw_bpf(unsigned cmd, const void *attr, unsigned size)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"((long)SYS_bpf), "D"((long)cmd), "S"(attr), "d"((long)size)
                     : "rcx", "r11", "memory");
    return result >= -4095 && result < 0 ? p11scope_verifier_errno((int)-result) : result;
}

static int output_fd(void)
{
    /* Workloads/helpers inherit the preload environment across fork/exec, but
     * pre-exec cleanup can close and reuse this FD number. Never instrument or
     * write through it from a descendant, including a freshly exec'd one. */
    if (probe_owner != getpid()) return -1;
    const char *text = getenv("P11SCOPE_VERIFIER_STATS_FD");
    if (!text || !*text) return -1;
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    return errno || *end || value < 3 || value > 1048576 ? -1 : (int)value;
}

static int write_line(int fd, const char *line)
{
    size_t length = strlen(line);
    for (unsigned attempts = 0; attempts < 4; attempts++) {
        ssize_t written = write(fd, line, length);
        if (written >= 0) return (size_t)written == length ? 0 : -1;
        if (errno != EINTR) return -1;
    }
    return -1;
}

static void emit(int fd, const char *line)
{
    uint64_t row = atomic_fetch_add_explicit(&emitted_rows, 1, memory_order_relaxed);
    if (row > 4000) return;
    if (row == 4000) line = "{\"record\":\"probe-error\",\"reason\":\"record-bound\"}\n";
    if (write_line(fd, line) != 0) atomic_fetch_add_explicit(&write_failures, 1, memory_order_relaxed);
}

__attribute__((destructor))
static void summarize_probe(void)
{
    int saved = errno, fd = output_fd();
    if (fd >= 0) {
        char line[256];
        uint64_t rows = atomic_load_explicit(&emitted_rows, memory_order_relaxed);
        snprintf(line, sizeof(line), "{\"record\":\"probe-summary\",\"pid\":%ld,\"records\":%llu,"
                 "\"write_failures\":%llu,\"overflow\":%s}\n", (long)getpid(),
                 (unsigned long long)rows,
                 (unsigned long long)atomic_load_explicit(&write_failures, memory_order_relaxed),
                 rows > 4000 ? "true" : "false");
        /* An absent summary fails acquisition too. Never alter loader status
         * because instrumentation could not write its own bounded result. */
        (void)write_line(fd, line);
    }
    errno = saved;
}

static void probe_error(int fd, const char *reason)
{
    char line[256];
    snprintf(line, sizeof(line), "{\"record\":\"probe-error\",\"reason\":\"%s\"}\n", reason);
    emit(fd, line);
}

static uint32_t word32(const unsigned char *where)
{
    uint32_t value;
    memcpy(&value, where, sizeof(value));
    return value;
}

/* BTF kinds are the published Linux UAPI layouts, including ENUM64. Unknown
 * kinds or malformed bounds refuse full-name resolution, never guess offsets. */
static int root_from_btf(const unsigned char *data, size_t length, uint32_t wanted,
                         char root[ROOT_BYTES])
{
    struct btf_header header;
    if (length < sizeof(header)) return -1;
    memcpy(&header, data, sizeof(header));
    if (header.magic != BTF_MAGIC || header.version != BTF_VERSION || header.flags ||
        header.hdr_len < sizeof(header) || header.hdr_len > length) return -1;
    size_t body = length - header.hdr_len;
    if (header.type_off > body || header.type_len > body - header.type_off ||
        header.str_off > body || header.str_len > body - header.str_off) return -1;
    const unsigned char *types = data + header.hdr_len + header.type_off;
    const char *strings = (const char *)data + header.hdr_len + header.str_off;
    size_t offset = 0;
    for (uint32_t id = 1; offset < header.type_len; id++) {
        if (header.type_len - offset < sizeof(struct btf_type)) return -1;
        uint32_t name = word32(types + offset), info = word32(types + offset + 4);
        unsigned kind = (info >> 24) & 31, count = info & 0xffff;
        size_t extra;
        switch (kind) {
        case BTF_KIND_INT: case BTF_KIND_VAR: case BTF_KIND_DECL_TAG: extra = 4; break;
        case BTF_KIND_ARRAY: extra = 12; break;
        case BTF_KIND_STRUCT: case BTF_KIND_UNION: case BTF_KIND_DATASEC:
        case BTF_KIND_ENUM64: extra = 12U * count; break;
        case BTF_KIND_ENUM: case BTF_KIND_FUNC_PROTO: extra = 8U * count; break;
        case BTF_KIND_PTR: case BTF_KIND_FWD: case BTF_KIND_TYPEDEF:
        case BTF_KIND_VOLATILE: case BTF_KIND_CONST: case BTF_KIND_RESTRICT:
        case BTF_KIND_FUNC: case BTF_KIND_FLOAT: case BTF_KIND_TYPE_TAG: extra = 0; break;
        default: return -1;
        }
        if (extra > header.type_len - offset - sizeof(struct btf_type)) return -1;
        if (id == wanted) {
            if (kind != BTF_KIND_FUNC || name >= header.str_len) return -1;
            const char *end = memchr(strings + name, 0, header.str_len - name);
            if (!end || end == strings + name || (size_t)(end - strings - name) >= ROOT_BYTES) return -1;
            size_t n = (size_t)(end - strings - name);
            for (size_t i = 0; i < n; i++) {
                unsigned char c = (unsigned char)strings[name + i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '$')) return -1;
            }
            memcpy(root, strings + name, n);
            root[n] = 0;
            return 0;
        }
        offset += sizeof(struct btf_type) + extra;
    }
    return -1;
}

static void remember_btf(int fd, const union bpf_attr *attr, int out)
{
    if (!attr->btf || attr->btf_size < sizeof(struct btf_header) || attr->btf_size > BTF_BYTES) {
        probe_error(out, "btf-byte-bound");
        return;
    }
    struct bpf_btf_info info = {0};
    union bpf_attr query = {0};
    query.info.bpf_fd = (uint32_t)fd;
    query.info.info_len = sizeof(info); query.info.info = (uint64_t)(uintptr_t)&info;
    if (raw_bpf(BPF_OBJ_GET_INFO_BY_FD, &query, sizeof(query)) != 0 || !info.id) {
        probe_error(out, "btf-fd-identity");
        return;
    }
    pthread_mutex_lock(&probe_lock);
    unsigned slot;
    for (slot = 0; slot < BTF_SLOTS; slot++) if (!btfs[slot].bytes || btfs[slot].fd == fd) break;
    if (slot == BTF_SLOTS || attr->btf_size > TOTAL_BTF_BYTES - btf_total) {
        probe_error(out, "btf-cache-bound");
    } else {
        unsigned char *copy = malloc(attr->btf_size);
        if (!copy) probe_error(out, "btf-allocation");
        else {
            memcpy(copy, (const void *)(uintptr_t)attr->btf, attr->btf_size);
            btf_total -= btfs[slot].length;
            free(btfs[slot].bytes);
            btfs[slot].fd = fd; btfs[slot].id = info.id;
            btfs[slot].bytes = copy; btfs[slot].length = attr->btf_size;
            btf_total += attr->btf_size;
        }
    }
    pthread_mutex_unlock(&probe_lock);
}

static int statistics(const char *text, size_t length, uint64_t *processed, uint64_t *limit)
{
    /* Kernels through 7.0 print one summary line; 7.2 prepends an `insns
     * processed A+B+...` phase-breakdown line that never parses as a
     * summary. Accept exactly one parseable summary wherever it sits, so
     * a doubled summary still fails closed. */
    const char *end = text + length;
    const char *cursor = text;
    unsigned long long a = 0, b = 0;
    int found = 0;
    while (cursor < end) {
        const char *hit = strstr(cursor, "processed ");
        if (!hit || hit >= end) break;
        unsigned long long x, y;
        int consumed = 0;
        if (sscanf(hit, "processed %llu insns (limit %llu)%n", &x, &y, &consumed) == 2 &&
            consumed > 0 && hit + consumed <= end &&
            x != 0 && y != 0 && x <= UINT32_MAX && y <= UINT32_MAX) {
            a = x; b = y; found++;
        }
        cursor = hit + 1;
    }
    if (found != 1) return -1;
    *processed = a; *limit = b;
    return 0;
}

static uint64_t hash_bytes(const void *data, size_t length)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    const unsigned char *bytes = data;
    for (size_t i = 0; i < length; i++) {
        hash ^= bytes[i]; hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t instruction_hash(const union bpf_attr *attr)
{
    if (!attr->insns || !attr->insn_cnt || attr->insn_cnt > 1000000) return 0;
    return hash_bytes((const void *)(uintptr_t)attr->insns,
                      (size_t)attr->insn_cnt * sizeof(struct bpf_insn));
}

typedef union { union bpf_attr known; unsigned char bytes[ATTR_BYTES]; } LoadCopy;

/* Six source forms, not an exemption for arbitrary small/unresolved programs.
 * Native counting_insns and pinned Aya's sys/{bpf,feature_probe}.rs own these
 * bytes. Every attribute outside the listed source inputs must remain zero. */
#define I(c, d, s, o, m) { .code = (c), .dst_reg = (d), .src_reg = (s), .off = (o), .imm = (m) }
static const struct bpf_insn pid_template[] = {
    I(0x62,10,0,-4,0), I(0xbf,2,10,0,0), I(0x07,2,0,0,-4), I(0x18,1,1,0,0),
    I(0,0,0,0,0), I(0x85,0,0,0,1), I(0x15,0,0,2,0), I(0xb7,1,0,0,1),
    I(0xdb,0,1,0,0), I(0xb7,0,0,0,0), I(0x95,0,0,0,0),
};
static const struct bpf_insn trivial_template[] = {I(0xb7,0,0,0,0), I(0x95,0,0,0,0)};
static const struct bpf_insn helper113_template[] = {I(0x85,0,0,0,113), I(0x95,0,0,0,0)};
static const struct bpf_insn global_template[] = {
    I(0x18,1,2,0,0), I(0,0,0,0,0), I(0x7a,1,0,0,42), I(0xb7,0,0,0,0), I(0x95,0,0,0,0),
};
static const struct bpf_insn helper174_template[] = {I(0x85,0,0,0,174), I(0x95,0,0,0,0)};
#undef I

static const struct auxiliary_form {
    const char *kind, *name;
    unsigned type, attach, count;
    const struct bpf_insn *instructions;
    int map_offset;
    unsigned map_value, helper_log;
} auxiliary_forms[] = {
    {"pid-filter", "p11scope_pidflt", 2, 48, 11, pid_template, 28, 8, 0},
    {"aya-name", "aya_name_check", 5, 0, 2, trivial_template, -1, 0, 0},
    {"aya-perf-link", "", 5, 0, 2, trivial_template, -1, 0, 0},
    {"aya-helper113", "", 5, 0, 2, helper113_template, -1, 0, 1},
    {"aya-global-data", "", 1, 0, 5, global_template, 4, 32, 0},
    {"aya-helper174", "", 2, 0, 2, helper174_template, -1, 0, 1},
};

struct auxiliary {
    const struct auxiliary_form *form;
    uint64_t template_hash;
    int map_fd;
    struct bpf_map_info map;
};

static uint32_t version_code(const char *text)
{
    unsigned major, minor, patch;
    if (sscanf(text, "%u.%u.%u", &major, &minor, &patch) != 3 || major > 255 || minor > 255) return 0;
    return (major << 16) | (minor << 8) | (patch > 255 ? 255 : patch);
}

static uint32_t source_kernel_version(void)
{
    /* Aya KernelVersion resolves Ubuntu's signature, then Debian's version,
     * then uname.release. A failed source lookup may leave kern_version=0. */
    char signature[256];
    FILE *file = fopen("/proc/version_signature", "re");
    if (file) {
        char *line = fgets(signature, sizeof(signature), file);
        fclose(file);
        char version[128];
        if (line && sscanf(signature, "%*s %*s %127s", version) == 1) {
            uint32_t code = version_code(version);
            if (code) return code;
        }
    }
    struct utsname info;
    if (uname(&info) != 0) return 0;
    const char *debian = strstr(info.version, "Debian ");
    return version_code(debian ? debian + 7 : info.release);
}

static int read_map_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr query = {0};
    query.info.bpf_fd = (uint32_t)fd;
    query.info.info_len = sizeof(*info);
    query.info.info = (uint64_t)(uintptr_t)info;
    return raw_bpf(BPF_OBJ_GET_INFO_BY_FD, &query, sizeof(query)) == 0 ? 0 : -1;
}

static int classify_auxiliary(const union bpf_attr *attr, unsigned size, uint32_t kernel_version,
                              int (*map_info)(int, struct bpf_map_info *), struct auxiliary *out)
{
    memset(out, 0, sizeof(*out));
    if (!attr || size > ATTR_BYTES || size < offsetof(union bpf_attr, func_info_cnt) + sizeof(attr->func_info_cnt) ||
        !attr->insns || !attr->license || memcmp((const void *)(uintptr_t)attr->license, "GPL", 4)) return 0;
    for (unsigned c = 0; c < sizeof(auxiliary_forms) / sizeof(auxiliary_forms[0]); c++) {
        const struct auxiliary_form *form = &auxiliary_forms[c];
        char name[16] = {0};
        memcpy(name, form->name, strlen(form->name));
        if (attr->prog_type != form->type || attr->expected_attach_type != form->attach ||
            attr->insn_cnt != form->count || memcmp(attr->prog_name, name, sizeof(name))) continue;
        if (attr->kern_version && !(c == 5 && kernel_version && attr->kern_version == kernel_version)) continue;
        if (form->helper_log) {
            if (attr->log_level != 1 || attr->log_size != 4096 || !attr->log_buf) continue;
        } else if (attr->log_level || attr->log_size || attr->log_buf) continue;
        LoadCopy remaining = {0};
        memcpy(remaining.bytes, attr, size);
        remaining.known.prog_type = 0; remaining.known.expected_attach_type = 0;
        remaining.known.insn_cnt = 0; remaining.known.insns = 0; remaining.known.license = 0;
        remaining.known.kern_version = 0;
        remaining.known.log_level = 0; remaining.known.log_size = 0; remaining.known.log_buf = 0;
        memset(remaining.known.prog_name, 0, sizeof(remaining.known.prog_name));
        unsigned nonzero = 0;
        for (unsigned i = 0; i < size; i++) nonzero |= remaining.bytes[i];
        if (nonzero) continue; /* Includes every BTF/func/line/attach/unknown-tail field. */
        unsigned char instructions[sizeof(pid_template)];
        size_t bytes = form->count * sizeof(struct bpf_insn);
        memcpy(instructions, (const void *)(uintptr_t)attr->insns, bytes);
        const unsigned char *wanted = (const unsigned char *)form->instructions;
        unsigned differs = 0;
        for (size_t i = 0; i < bytes; i++) {
            if (form->map_offset >= 0 && i >= (size_t)form->map_offset && i < (size_t)form->map_offset + 4) continue;
            differs |= instructions[i] ^ wanted[i];
        }
        if (differs) continue;
        struct bpf_map_info map = {0};
        int32_t fd = -1;
        if (form->map_offset >= 0) {
            memcpy(&fd, instructions + form->map_offset, sizeof(fd));
            if (fd < 0 || !map_info) continue;
            int saved = errno;
            int valid = map_info(fd, &map);
            errno = saved;
            if (valid != 0 || !map.id || map.type != BPF_MAP_TYPE_ARRAY || map.key_size != 4 ||
                map.value_size != form->map_value || map.max_entries != 1 || map.map_flags) continue;
            /* Only now normalize the one validated FD in our local copy.
             * The actual loader instructions and attributes are untouched. */
            memset(instructions + form->map_offset, 0, sizeof(fd));
        }
        out->form = form; out->map_fd = fd; out->map = map;
        out->template_hash = hash_bytes(instructions, bytes);
        return 1;
    }
    return 0;
}

static int auxiliary_json(const struct auxiliary *auxiliary, char *out, size_t size)
{
    int length;
    if (!auxiliary->form) length = snprintf(out, size, "null");
    else {
        char mapping[256] = "null";
        if (auxiliary->map_fd >= 0) {
            length = snprintf(mapping, sizeof(mapping),
                "{\"fd\":%d,\"id\":%u,\"type\":%u,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":%u}",
                auxiliary->map_fd, auxiliary->map.id, auxiliary->map.type, auxiliary->map.key_size,
                auxiliary->map.value_size, auxiliary->map.max_entries, auxiliary->map.map_flags);
            if (length < 0 || (size_t)length >= sizeof(mapping)) return -1;
        }
        length = snprintf(out, size,
            "{\"kind\":\"%s\",\"name\":\"%s\",\"template_fnv1a64\":\"%016llx\",\"map\":%s}",
            auxiliary->form->kind, auxiliary->form->name,
            (unsigned long long)auxiliary->template_hash, mapping);
    }
    return length < 0 || (size_t)length >= size ? -1 : 0;
}

static int prepare_load(LoadCopy *copy, const union bpf_attr *attr, unsigned size, void *log)
{
    if (!attr || size > ATTR_BYTES || size < offsetof(union bpf_attr, func_info_cnt) + sizeof(attr->func_info_cnt)) return -1;
    memset(copy, 0, sizeof(*copy));
    memcpy(copy->bytes, attr, size);
    copy->known.log_level = 4;
    copy->known.log_buf = (uint64_t)(uintptr_t)log;
    copy->known.log_size = LOG_BYTES;
    return 0;
}

__attribute__((visibility("hidden")))
long p11scope_verifier_bpf(long number, unsigned cmd, const union bpf_attr *attr, unsigned size)
{
    (void)number;
    int entered_errno = errno, out = output_fd();
    errno = entered_errno;
    if (out < 0) return raw_bpf(cmd, attr, size);
    if (cmd == BPF_BTF_LOAD) {
        long result = raw_bpf(cmd, attr, size);
        int saved = errno;
        if (result >= 0) remember_btf((int)result, attr, out);
        errno = saved;
        return result;
    }
    if (cmd != BPF_PROG_LOAD) return raw_bpf(cmd, attr, size);
    if (!attr || size > ATTR_BYTES || size < offsetof(union bpf_attr, func_info_cnt) + sizeof(attr->func_info_cnt)) {
        probe_error(out, "program-attribute-bound");
        errno = entered_errno;
        return raw_bpf(cmd, attr, size);
    }
    LoadCopy copy;
    char *log = calloc(1, LOG_BYTES);
    if (!log) {
        probe_error(out, "log-allocation"); errno = entered_errno;
        return raw_bpf(cmd, attr, size);
    }
    if (prepare_load(&copy, attr, size, log) != 0) {
        free(log); probe_error(out, "program-copy-bound"); errno = entered_errno;
        return raw_bpf(cmd, attr, size);
    }
    char root[ROOT_BYTES] = "unresolved";
    uint32_t root_type = 0, btf_id = 0;
    int resolved = -1;
    if (attr->func_info && attr->func_info_cnt && attr->func_info_rec_size >= sizeof(struct bpf_func_info)) {
        struct bpf_func_info first;
        memcpy(&first, (const void *)(uintptr_t)attr->func_info, sizeof(first));
        if (first.insn_off == 0) {
            root_type = first.type_id;
            pthread_mutex_lock(&probe_lock);
            for (unsigned i = 0; i < BTF_SLOTS; i++) if (btfs[i].bytes && btfs[i].fd == (int)attr->prog_btf_fd) {
                resolved = root_from_btf(btfs[i].bytes, btfs[i].length, root_type, root);
                btf_id = btfs[i].id;
                break;
            }
            pthread_mutex_unlock(&probe_lock);
        }
    }
    uint64_t hash = instruction_hash(attr);
    struct auxiliary auxiliary = {0};
    if (resolved != 0) {
        uint32_t kernel_version = attr->kern_version ? source_kernel_version() : 0;
        (void)classify_auxiliary(attr, size, kernel_version, read_map_info, &auxiliary);
    }
    errno = entered_errno;
    long result = raw_bpf(cmd, copy.bytes, size);
    int saved = errno;
    size_t length = strnlen(log, LOG_BYTES);
    uint64_t processed = 0, limit = 0;
    int stats = length < LOG_BYTES ? statistics(log, length, &processed, &limit) : -1;
    struct bpf_prog_info info = {0};
    union bpf_attr query = {0};
    query.info.bpf_fd = result >= 0 ? (uint32_t)result : 0;
    query.info.info_len = sizeof(info); query.info.info = (uint64_t)(uintptr_t)&info;
    int identified = result >= 0 && raw_bpf(BPF_OBJ_GET_INFO_BY_FD, &query, sizeof(query)) == 0;
    char line[1536], provenance[512];
    if (auxiliary_json(&auxiliary, provenance, sizeof(provenance)) != 0) {
        probe_error(out, "auxiliary-byte-bound");
        memcpy(provenance, "null", 5);
    }
    int line_length = snprintf(line, sizeof(line),
        "{\"record\":\"load\",\"pid\":%ld,\"root\":\"%s\",\"btf_resolved\":%s,"
        "\"btf_fd\":%u,\"btf_id\":%u,\"returned_btf_id\":%u,\"root_type_id\":%u,"
        "\"returned_fd\":%ld,\"program_id\":%u,"
        "\"program_type\":%u,\"returned_program_type\":%u,\"program_flags\":%u,"
        "\"expected_attach_type\":%u,\"insn_count\":%u,\"relocated_fnv1a64\":\"%016llx\","
        "\"loaded\":%s,\"errno\":%d,\"stats_present\":%s,\"processed\":%llu,\"limit\":%llu,\"auxiliary\":%s}\n",
        (long)getpid(), root, resolved == 0 ? "true" : "false", attr->prog_btf_fd,
        btf_id, identified ? info.btf_id : 0, root_type,
        result, identified ? info.id : 0, attr->prog_type, identified ? info.type : 0,
        attr->prog_flags, attr->expected_attach_type, attr->insn_cnt, (unsigned long long)hash,
        result >= 0 ? "true" : "false", result < 0 ? saved : 0, stats == 0 ? "true" : "false",
        (unsigned long long)processed, (unsigned long long)limit, provenance);
    pthread_mutex_lock(&probe_lock);
    if (line_length < 0 || (size_t)line_length >= sizeof(line)) probe_error(out, "record-byte-bound");
    else emit(out, line);
    pthread_mutex_unlock(&probe_lock);
    if (attr->log_buf && attr->log_size) {
        /* Preserve the loader's normal diagnostic buffer on a failed load.
         * Its log pointer/capacity is never retained after this syscall. */
        size_t n = length < attr->log_size - 1 ? length : attr->log_size - 1;
        memcpy((void *)(uintptr_t)attr->log_buf, log, n);
        ((char *)(uintptr_t)attr->log_buf)[n] = 0;
    }
    free(log);
    errno = saved;
    return result;
}
#endif

#ifdef PROBE_SELF_TEST
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifndef PROBE_FORWARD_ONLY
static struct bpf_map_info test_map;
static unsigned test_map_reads;
static int test_map_failure, test_map_fd = 7;

static int test_map_query(int fd, struct bpf_map_info *info)
{
    test_map_reads++;
    errno = EIO;
    if (test_map_failure || fd != test_map_fd) return -1;
    *info = test_map;
    return 0;
}

static void test_auxiliaries(int dump)
{
    /* Independent literal source instructions, not the matcher's templates. */
    const struct bpf_insn pid[] = {
        {0x62, 10, 0, -4, 0}, {0xbf, 2, 10, 0, 0}, {0x07, 2, 0, 0, -4},
        {0x18, 1, 1, 0, 7}, {0, 0, 0, 0, 0}, {0x85, 0, 0, 0, 1},
        {0x15, 0, 0, 2, 0}, {0xb7, 1, 0, 0, 1}, {0xdb, 0, 1, 0, 0},
        {0xb7, 0, 0, 0, 0}, {0x95, 0, 0, 0, 0},
    };
    const struct bpf_insn trivial[] = {{0xb7, 0, 0, 0, 0}, {0x95, 0, 0, 0, 0}};
    const struct bpf_insn read_kernel[] = {{0x85, 0, 0, 0, 113}, {0x95, 0, 0, 0, 0}};
    const struct bpf_insn global[] = {
        {0x18, 1, 2, 0, 7}, {0, 0, 0, 0, 0}, {0x7a, 1, 0, 0, 42},
        {0xb7, 0, 0, 0, 0}, {0x95, 0, 0, 0, 0},
    };
    const struct bpf_insn cookie[] = {{0x85, 0, 0, 0, 174}, {0x95, 0, 0, 0, 0}};
    const struct {
        const char *kind, *name;
        unsigned type, attach, count, value_size;
        const struct bpf_insn *insns;
        uint64_t template_hash;
    } cases[] = {
        {"pid-filter", "p11scope_pidflt", 2, 48, 11, 8, pid, UINT64_C(0xd8233289cdbfd0db)},
        {"aya-name", "aya_name_check", 5, 0, 2, 0, trivial, UINT64_C(0x58255400910d7827)},
        {"aya-perf-link", "", 5, 0, 2, 0, trivial, UINT64_C(0x58255400910d7827)},
        {"aya-helper113", "", 5, 0, 2, 0, read_kernel, UINT64_C(0x382112bd35027674)},
        {"aya-global-data", "", 1, 0, 5, 32, global, UINT64_C(0x048f9e0260e5b0fb)},
        {"aya-helper174", "", 2, 0, 2, 0, cookie, UINT64_C(0xb10c1c56d90769db)},
    };
    char helper_log[4096];
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        struct bpf_insn instructions[11] = {0};
        memcpy(instructions, cases[c].insns, cases[c].count * sizeof(*instructions));
        LoadCopy original = {0}, changed;
        original.known.prog_type = cases[c].type;
        original.known.expected_attach_type = cases[c].attach;
        original.known.insn_cnt = cases[c].count;
        original.known.insns = (uint64_t)(uintptr_t)instructions;
        original.known.license = (uint64_t)(uintptr_t)"GPL";
        memcpy(original.known.prog_name, cases[c].name, strlen(cases[c].name));
        if (c == 3 || c == 5) {
            original.known.log_level = 1;
            original.known.log_size = sizeof(helper_log);
            original.known.log_buf = (uint64_t)(uintptr_t)helper_log;
        }
        if (c == 5) original.known.kern_version = 0x070209;
        test_map = (struct bpf_map_info){.type = BPF_MAP_TYPE_ARRAY, .id = 401,
            .key_size = 4, .value_size = cases[c].value_size, .max_entries = 1};
        test_map_failure = 0; test_map_reads = 0;
        struct auxiliary auxiliary;
        LoadCopy unchanged = original;
        errno = ECHILD;
        assert(classify_auxiliary(&original.known, sizeof(original), 0x070209,
                                  test_map_query, &auxiliary));
        assert(errno == ECHILD);
        assert(strcmp(auxiliary.form->kind, cases[c].kind) == 0);
        assert(auxiliary.template_hash == cases[c].template_hash);
        assert(test_map_reads == (cases[c].value_size ? 1U : 0U));
        assert(memcmp(&original, &unchanged, sizeof(original)) == 0);
        assert(memcmp(instructions, cases[c].insns, cases[c].count * sizeof(*instructions)) == 0);
        char json[512];
        assert(auxiliary_json(&auxiliary, json, sizeof(json)) == 0);
        if (dump) puts(json);
        assert(auxiliary_json(&auxiliary, json, 4) != 0);
        for (unsigned byte = 0; byte < cases[c].count * sizeof(*instructions); byte++) {
            ((unsigned char *)instructions)[byte] ^= 1;
            assert(!classify_auxiliary(&original.known, sizeof(original), 0x070209,
                                      test_map_query, &auxiliary));
            ((unsigned char *)instructions)[byte] ^= 1;
        }
#define REJECT_FIELD(field, value) do { changed = original; changed.known.field = (value); \
    assert(!classify_auxiliary(&changed.known, sizeof(changed), 0x070209, test_map_query, &auxiliary)); } while (0)
        REJECT_FIELD(prog_type, 99);
        REJECT_FIELD(expected_attach_type, 99);
        REJECT_FIELD(prog_flags, 1);
        REJECT_FIELD(prog_ifindex, 1);
        REJECT_FIELD(prog_btf_fd, 4);
        REJECT_FIELD(func_info, 8);
        REJECT_FIELD(func_info_cnt, 1);
        REJECT_FIELD(func_info_rec_size, sizeof(struct bpf_func_info));
        REJECT_FIELD(line_info, 8);
        REJECT_FIELD(line_info_cnt, 1);
        REJECT_FIELD(attach_btf_id, 1);
        REJECT_FIELD(license, (uint64_t)(uintptr_t)"MIT");
        REJECT_FIELD(insn_cnt, 12);
        REJECT_FIELD(insns, 0);
        REJECT_FIELD(log_level, 2);
        REJECT_FIELD(kern_version, 0x010203);
#undef REJECT_FIELD
        changed = original; changed.known.prog_name[0] ^= 1;
        assert(!classify_auxiliary(&changed.known, sizeof(changed), 0x070209,
                                  test_map_query, &auxiliary));
        changed = original; changed.bytes[ATTR_BYTES - 1] = 1;
        assert(!classify_auxiliary(&changed.known, sizeof(changed), 0x070209,
                                  test_map_query, &auxiliary));
        assert(!classify_auxiliary(&original.known, 1, 0x070209, test_map_query, &auxiliary));
        if (cases[c].value_size) {
            unsigned map_insn = c == 0 ? 3 : 0;
            instructions[map_insn].imm = 8; test_map_fd = 8;
            assert(classify_auxiliary(&original.known, sizeof(original), 0x070209,
                                      test_map_query, &auxiliary));
            assert(auxiliary.map_fd == 8 && auxiliary.template_hash == cases[c].template_hash);
            instructions[map_insn].imm = 7; test_map_fd = 7;
            struct bpf_map_info healthy = test_map;
#define REJECT_MAP(field, value) do { test_map = healthy; test_map.field = (value); \
    assert(!classify_auxiliary(&original.known, sizeof(original), 0x070209, test_map_query, &auxiliary)); } while (0)
            REJECT_MAP(id, 0);
            REJECT_MAP(type, BPF_MAP_TYPE_HASH);
            REJECT_MAP(key_size, 8);
            REJECT_MAP(value_size, 16);
            REJECT_MAP(max_entries, 2);
            REJECT_MAP(map_flags, 1);
#undef REJECT_MAP
            test_map = healthy; test_map_failure = 1;
            assert(!classify_auxiliary(&original.known, sizeof(original), 0x070209,
                                      test_map_query, &auxiliary));
            test_map_failure = 0;
        }
    }
    if (!dump) puts("verifier probe: six exact auxiliary forms and refusal twins PASS");
}
#endif
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--descendant") == 0) return 0;
#ifndef PROBE_FORWARD_ONLY
    if (argc == 2 && strcmp(argv[1], "--auxiliary-records") == 0) {
        test_auxiliaries(1);
        return 0;
    }
    assert(version_code("7.2.9-200.fc44.x86_64") == 0x070209);
    assert(version_code("5.15.221") == 0x050fdd);
    assert(version_code("6.1.300") == 0x0601ff);
    assert(version_code("invalid") == 0);
    test_auxiliaries(0);
    uint64_t a, b;
    const char *good = "verification time 17 usec\nstack depth 192+264\nprocessed 950000 insns (limit 1000000) max_states_per_insn 1\n";
    assert(statistics(good, strlen(good), &a, &b) == 0 && a == 950000 && b == 1000000);
    /* 7.2 prepends a phase-breakdown line that never parses as a summary;
     * the classic summary line still carries the counts. */
    const char *good72 = "verification time 223322 usec\nstack depth 192+32 max 272\ninsns processed 22116+54+292+941+448+27\nprocessed 23878 insns (limit 1000000) max_states_per_insn 14 total_states 1969 peak_states 1882 mark_read 0\n";
    assert(statistics(good72, strlen(good72), &a, &b) == 0 && a == 23878 && b == 1000000);
    const char *bad[] = {"", "processed 0 insns (limit 1000000)", "processed 1 insns (limit 0)",
        "processed 4294967296 insns (limit 1000000)", "processed 1 insns (limit 1000000",
        "processed 1 insns (limit 1000000) processed 2 insns (limit 1000000)"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) assert(statistics(bad[i], strlen(bad[i]), &a, &b) != 0);
    const char names[] = "\0int\0p11_entry_template_pair\0";
    struct { struct btf_header h; uint32_t types[10]; char strings[sizeof(names)]; } fixture = {
        .h = { .magic = BTF_MAGIC, .version = BTF_VERSION, .hdr_len = sizeof(struct btf_header),
               .type_len = 40, .str_off = 40, .str_len = sizeof(names) },
        .types = {1, BTF_KIND_INT << 24, 4, 32, 0, BTF_KIND_FUNC_PROTO << 24, 1,
                  5, (BTF_KIND_FUNC << 24) | BTF_FUNC_GLOBAL, 2},
    };
    memcpy(fixture.strings, names, sizeof(names));
    char root[ROOT_BYTES];
    assert(root_from_btf((unsigned char *)&fixture, sizeof(fixture), 3, root) == 0);
    assert(strcmp(root, "p11_entry_template_pair") == 0);
    assert(root_from_btf((unsigned char *)&fixture, sizeof(fixture), 2, root) != 0);
    assert(root_from_btf((unsigned char *)&fixture, sizeof(fixture), 4, root) != 0);
    fixture.h.str_len = 5;
    assert(root_from_btf((unsigned char *)&fixture, sizeof(fixture), 3, root) != 0);
    LoadCopy original, changed;
    memset(&original, 0xa5, sizeof(original));
    char log[64];
    assert(prepare_load(&changed, &original.known, ATTR_BYTES, log) == 0);
    for (size_t i = 0; i < ATTR_BYTES; i++) {
        int logging = (i >= offsetof(union bpf_attr, log_level) && i < offsetof(union bpf_attr, log_level) + 4) ||
                      (i >= offsetof(union bpf_attr, log_size) && i < offsetof(union bpf_attr, log_size) + 4) ||
                      (i >= offsetof(union bpf_attr, log_buf) && i < offsetof(union bpf_attr, log_buf) + 8);
        if (!logging) assert(changed.bytes[i] == original.bytes[i]);
    }
    assert(changed.known.log_level == 4 && changed.known.log_size == LOG_BYTES &&
           changed.known.log_buf == (uint64_t)(uintptr_t)log);
    assert(prepare_load(&changed, &original.known, ATTR_BYTES + 1, log) != 0);
    assert(prepare_load(&changed, &original.known, 1, log) != 0);
#endif
    /* Actual native zero/one/two/six-argument forwarding, with a nonzero
     * sixth mmap offset. A dead-varargs forwarding implementation is absent. */
    assert(syscall(SYS_getpid) == getpid());
    assert(syscall(SYS_close, -1) == -1 && errno == EBADF);
    int fd = memfd_create("verifier-probe-forwarding", 0); assert(fd >= 0);
    assert(syscall(SYS_ftruncate, fd, 8192) == 0);
    char byte = 'Z'; assert(pwrite(fd, &byte, 1, 4096) == 1);
    void *page = (void *)syscall(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, fd, 4096);
    assert(page != MAP_FAILED && *(char *)page == 'Z');
    assert(munmap(page, 4096) == 0 && close(fd) == 0);
    assert(syscall(0x7fffffff) == -1 && errno == ENOSYS);
    const char *out = getenv("P11SCOPE_VERIFIER_STATS_FD");
    if (out) {
        char *end;
        long log_fd = strtol(out, &end, 10);
        assert(!*end && log_fd >= 3 && log_fd <= 1048576);
        int target = memfd_create("verifier-probe-descendant", 0);
        assert(target >= 0 && target != log_fd);
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            assert(dup2(target, (int)log_fd) == log_fd);
            assert(close(target) == 0);
            execl("/proc/self/exe", "probe-descendant", "--descendant", (char *)NULL);
            _exit(125);
        }
        int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        struct stat observed;
        assert(fstat(target, &observed) == 0 && observed.st_size == 0);
        assert(close(target) == 0);
        puts("verifier probe: descendant exec and reused FD remain byte-empty PASS");
    }
#ifdef PROBE_FORWARD_ONLY
    puts("verifier probe: actual shared-preload syscall forwarding PASS");
#else
    puts("verifier probe: stats/BTF refusal controls and native syscall ABI PASS");
#endif
    return 0;
}
#endif
