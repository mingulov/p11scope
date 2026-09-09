#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct bpf_object;
struct bpf_map;
struct bpf_program;
struct bpf_link;

enum { MAP_COUNT = 3, HEADER_SIZE = 28, LOG_LIMIT = 8192 };
static const unsigned char raw_magic[8] = {'P', '1', '1', 'T', 'S', 'R', '1', 0};
static const unsigned char output_magic[8] = {'P', '1', '1', 'T', 'S', 'V', '1', 0};

struct map_spec {
    const char *name;
    uint32_t id;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    int fd;
    struct bpf_map *map;
};

struct frame_header {
    unsigned char magic[8];
    uint32_t kind;
    uint32_t map_id;
    uint32_t pid;
    uint32_t tid;
    uint32_t value_len;
} __attribute__((packed));

typedef int (*libbpf_print_fn)(int, const char *, va_list);

struct api {
    struct bpf_object *(*object_open_file)(const char *, const void *);
    long (*get_error)(const void *);
    struct bpf_map *(*object_find_map)(const struct bpf_object *, const char *);
    int (*map_reuse_fd)(struct bpf_map *, int);
    int (*object_load)(struct bpf_object *);
    int (*map_fd)(const struct bpf_map *);
    struct bpf_program *(*object_find_program)(const struct bpf_object *, const char *);
    struct bpf_link *(*program_attach_iter)(const struct bpf_program *, const void *);
    int (*link_fd)(const struct bpf_link *);
    int (*link_destroy)(struct bpf_link *);
    void (*object_close)(struct bpf_object *);
    libbpf_print_fn (*set_print)(libbpf_print_fn);
};

static size_t log_bytes;

static int bounded_libbpf_log(int level, const char *format, va_list args)
{
    char buffer[1024];
    int length;
    size_t emit;
    (void)level;
    if (log_bytes >= LOG_LIMIT)
        return 0;
    length = vsnprintf(buffer, sizeof(buffer), format, args);
    if (length <= 0)
        return length;
    emit = (size_t)length < sizeof(buffer) ? (size_t)length : sizeof(buffer) - 1;
    if (emit > LOG_LIMIT - log_bytes)
        emit = LOG_LIMIT - log_bytes;
    if (write(STDERR_FILENO, buffer, emit) < 0)
        return -1;
    log_bytes += emit;
    return length;
}

static int fail(const char *message)
{
    fprintf(stderr, "dump-task-storage: %s\n", message);
    return 1;
}

static bool error_pointer(const void *pointer)
{
    return (uintptr_t)pointer >= (uintptr_t)-4095;
}

static int bpf_fd_by_id(uint32_t id)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_id = id;
    return (int)syscall(SYS_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}

static int bpf_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr attr;
    uint32_t length = sizeof(*info);
    memset(info, 0, sizeof(*info));
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = length;
    attr.info.info = (uintptr_t)info;
    return (int)syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

static int bpf_iter_fd(int link_fd)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.iter_create.link_fd = (uint32_t)link_fd;
    attr.iter_create.flags = 0;
    return (int)syscall(SYS_bpf, BPF_ITER_CREATE, &attr, sizeof(attr));
}

static int parse_u32(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno || !end || *end || parsed > UINT32_MAX)
        return -1;
    *value = (uint32_t)parsed;
    return 0;
}

static int parse_spec(char *argument, struct map_spec *spec, const char *expected_name,
                      uint32_t expected_value)
{
    char *save = NULL;
    char *fields[7];
    size_t index;
    for (index = 0; index < 7; index++) {
        fields[index] = strtok_r(index ? NULL : argument, ":", &save);
        if (!fields[index])
            return -1;
    }
    if (strtok_r(NULL, ":", &save) || strcmp(fields[0], expected_name) ||
        strcmp(fields[2], "task_storage"))
        return -1;
    spec->name = expected_name;
    spec->fd = -1;
    if (parse_u32(fields[1], &spec->id) || parse_u32(fields[3], &spec->key_size) ||
        parse_u32(fields[4], &spec->value_size) ||
        parse_u32(fields[5], &spec->max_entries) ||
        parse_u32(fields[6], &spec->map_flags))
        return -1;
    if (spec->key_size != 4 || spec->value_size != expected_value ||
        spec->max_entries != 0 || spec->map_flags != BPF_F_NO_PREALLOC)
        return -1;
    return 0;
}

static bool info_matches(const struct bpf_map_info *info, const struct map_spec *spec)
{
    size_t name_length = strlen(spec->name);
    size_t kernel_name_length = name_length < BPF_OBJ_NAME_LEN - 1 ?
        name_length : BPF_OBJ_NAME_LEN - 1;
    return info->id == spec->id && info->type == BPF_MAP_TYPE_TASK_STORAGE &&
        info->key_size == spec->key_size && info->value_size == spec->value_size &&
        info->max_entries == spec->max_entries && info->map_flags == spec->map_flags &&
        !memcmp(info->name, spec->name, kernel_name_length) &&
        info->name[kernel_name_length] == 0;
}

static int exact_info(int fd, const struct map_spec *spec)
{
    struct bpf_map_info info;
    return bpf_info(fd, &info) || !info_matches(&info, spec) ? -1 : 0;
}

static int load_symbol(void *library, const char *name, void **output)
{
    dlerror();
    *output = dlsym(library, name);
    return dlerror() || !*output ? -1 : 0;
}

#define LOAD(api, library, field, symbol) \
    do { if (load_symbol((library), (symbol), (void **)&(api)->field)) return -1; } while (0)

static int load_api(void *library, struct api *api)
{
    LOAD(api, library, object_open_file, "bpf_object__open_file");
    LOAD(api, library, get_error, "libbpf_get_error");
    LOAD(api, library, object_find_map, "bpf_object__find_map_by_name");
    LOAD(api, library, map_reuse_fd, "bpf_map__reuse_fd");
    LOAD(api, library, object_load, "bpf_object__load");
    LOAD(api, library, map_fd, "bpf_map__fd");
    LOAD(api, library, object_find_program, "bpf_object__find_program_by_name");
    LOAD(api, library, program_attach_iter, "bpf_program__attach_iter");
    LOAD(api, library, link_fd, "bpf_link__fd");
    LOAD(api, library, link_destroy, "bpf_link__destroy");
    LOAD(api, library, object_close, "bpf_object__close");
    LOAD(api, library, set_print, "libbpf_set_print");
    return 0;
}

static uint64_t monotonic_millis(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return UINT64_MAX;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;
    while (length) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        cursor += count;
        length -= (size_t)count;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static const char *names[MAP_COUNT] = {"TASK_COOKIE", "THREAD_OWNER", "ROOT_AFFILIATION"};
    static const uint32_t sizes[MAP_COUNT] = {8, 544, 8};
    struct map_spec specs[MAP_COUNT];
    struct api api;
    struct bpf_object *object = NULL;
    struct bpf_program *program = NULL;
    struct bpf_link *link = NULL;
    void *library = NULL;
    unsigned char *raw = NULL;
    uint32_t observer_pid, max_records, max_bytes, timeout_ms;
    size_t capacity, used = 0, offset = 0;
    uint32_t records = 0;
    uint64_t deadline;
    int iterator_fd = -1;
    int status = 1;
    size_t index;

    memset(&api, 0, sizeof(api));
    memset(specs, 0, sizeof(specs));
    for (index = 0; index < MAP_COUNT; index++)
        specs[index].fd = -1;
    if (argc == 2 && !strcmp(argv[1], "--self-test")) {
        struct bpf_map_info info;
        struct map_spec spec = {
            .name = "THREAD_OWNER", .id = 42, .key_size = 4, .value_size = 544,
            .max_entries = 0, .map_flags = BPF_F_NO_PREALLOC, .fd = -1,
        };
        memset(&info, 0, sizeof(info));
        info.id = 42;
        info.type = BPF_MAP_TYPE_TASK_STORAGE;
        info.key_size = 4;
        info.value_size = 544;
        info.max_entries = 0;
        info.map_flags = BPF_F_NO_PREALLOC;
        memcpy(info.name, spec.name, strlen(spec.name) + 1);
        if (!info_matches(&info, &spec))
            return fail("self-test rejected exact imported map");
        info.id++;
        if (info_matches(&info, &spec))
            return fail("self-test accepted replacement map id");
        info.id--;
        info.value_size--;
        if (info_matches(&info, &spec))
            return fail("self-test accepted truncated value metadata");
        info.value_size++;
        info.map_flags = 0;
        if (info_matches(&info, &spec))
            return fail("self-test accepted changed map flags");
        memset(&info, 0, sizeof(info));
        spec.name = "ROOT_AFFILIATION";
        spec.value_size = 8;
        info.id = spec.id;
        info.type = BPF_MAP_TYPE_TASK_STORAGE;
        info.key_size = spec.key_size;
        info.value_size = spec.value_size;
        info.map_flags = spec.map_flags;
        memcpy(info.name, spec.name, BPF_OBJ_NAME_LEN - 1);
        if (!info_matches(&info, &spec))
            return fail("self-test rejected canonical kernel-truncated map name");
        puts("dump-task-storage exact-map mutation self-test: OK");
        return 0;
    }
    if (argc != 9 || parse_u32(argv[2], &observer_pid) || !observer_pid ||
        parse_u32(argv[3], &max_records) || !max_records || max_records > 131072 ||
        parse_u32(argv[4], &max_bytes) || !max_bytes || max_bytes > 64U * 1024U * 1024U ||
        parse_u32(argv[5], &timeout_ms) || !timeout_ms || timeout_ms > 60000)
        return fail("invalid arguments");
    for (index = 0; index < MAP_COUNT; index++) {
        if (parse_spec(argv[6 + index], &specs[index], names[index], sizes[index]))
            return fail("invalid map specification");
    }
    if ((size_t)max_records > (SIZE_MAX - max_bytes) / HEADER_SIZE)
        return fail("framed output bound overflow");
    capacity = (size_t)max_bytes + (size_t)max_records * HEADER_SIZE;
    raw = malloc(capacity ? capacity : 1);
    if (!raw)
        return fail("bounded buffer allocation failed");
    library = dlopen("libbpf.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library || load_api(library, &api)) {
        fail("cannot load required libbpf.so.1 API");
        goto cleanup;
    }
    api.set_print(bounded_libbpf_log);
    for (index = 0; index < MAP_COUNT; index++) {
        specs[index].fd = bpf_fd_by_id(specs[index].id);
        if (specs[index].fd < 0 || exact_info(specs[index].fd, &specs[index])) {
            fail("exact input map identity or metadata mismatch");
            goto cleanup;
        }
    }
    object = api.object_open_file(argv[1], NULL);
    if (!object || error_pointer(object) || api.get_error(object)) {
        object = NULL;
        fail("cannot open iterator object");
        goto cleanup;
    }
    for (index = 0; index < MAP_COUNT; index++) {
        specs[index].map = api.object_find_map(object, specs[index].name);
        if (!specs[index].map || api.map_reuse_fd(specs[index].map, specs[index].fd)) {
            fail("cannot reuse exact task-storage map fd");
            goto cleanup;
        }
    }
    if (api.object_load(object)) {
        fail("cannot load task iterator");
        goto cleanup;
    }
    for (index = 0; index < MAP_COUNT; index++) {
        int object_fd = api.map_fd(specs[index].map);
        if (object_fd < 0 || exact_info(object_fd, &specs[index])) {
            fail("loaded object replaced an imported task-storage map");
            goto cleanup;
        }
    }
    program = api.object_find_program(object, "dump_task_storage");
    if (!program) {
        fail("iterator program is missing");
        goto cleanup;
    }
    link = api.program_attach_iter(program, NULL);
    if (!link || error_pointer(link) || api.get_error(link)) {
        link = NULL;
        fail("cannot attach task iterator");
        goto cleanup;
    }
    iterator_fd = bpf_iter_fd(api.link_fd(link));
    if (iterator_fd < 0) {
        fail("cannot create task iterator fd");
        goto cleanup;
    }
    deadline = monotonic_millis() + timeout_ms;
    while (used < capacity) {
        ssize_t count;
        if (monotonic_millis() > deadline) {
            fail("iterator read timed out");
            goto cleanup;
        }
        count = read(iterator_fd, raw + used, capacity - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            fail("iterator read failed");
            goto cleanup;
        }
        if (count == 0)
            break;
        used += (size_t)count;
    }
    if (used == capacity) {
        unsigned char extra;
        ssize_t count = read(iterator_fd, &extra, 1);
        if (count != 0) {
            fail("iterator output exceeded bound");
            goto cleanup;
        }
    }
    while (offset < used) {
        struct frame_header header;
        uint32_t slot;
        if (used - offset < sizeof(header)) {
            fail("iterator produced a truncated frame header");
            goto cleanup;
        }
        memcpy(&header, raw + offset, sizeof(header));
        offset += sizeof(header);
        slot = header.map_id;
        if (memcmp(header.magic, raw_magic, sizeof(raw_magic)) || header.kind != 1 ||
            slot >= MAP_COUNT || header.value_len != specs[slot].value_size ||
            !header.pid || !header.tid || header.value_len > used - offset) {
            fail("iterator produced invalid frame metadata");
            goto cleanup;
        }
        if (records == max_records) {
            fail("iterator record bound exceeded");
            goto cleanup;
        }
        records++;
        memcpy(header.magic, output_magic, sizeof(output_magic));
        header.map_id = specs[slot].id;
        if (write_all(STDOUT_FILENO, &header, sizeof(header)) ||
            write_all(STDOUT_FILENO, raw + offset, header.value_len)) {
            fail("cannot write framed output");
            goto cleanup;
        }
        offset += header.value_len;
    }
    {
        struct frame_header eof;
        memset(&eof, 0, sizeof(eof));
        memcpy(eof.magic, output_magic, sizeof(output_magic));
        eof.kind = 2;
        if (write_all(STDOUT_FILENO, &eof, sizeof(eof))) {
            fail("cannot write terminal EOF frame");
            goto cleanup;
        }
    }
    status = 0;

cleanup:
    if (iterator_fd >= 0)
        close(iterator_fd);
    if (link && api.link_destroy)
        api.link_destroy(link);
    if (object && api.object_close)
        api.object_close(object);
    for (index = 0; index < MAP_COUNT; index++) {
        if (specs[index].fd >= 0)
            close(specs[index].fd);
    }
    if (library)
        dlclose(library);
    free(raw);
    return status;
}
