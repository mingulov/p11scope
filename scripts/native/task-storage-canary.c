/* Test-only single-task task-storage seed fixture: creates the isolated three
 * map surface the unchanged reader dumps. It loads the existing iterator object
 * with every program's autoload disabled, so no program, link, attachment or
 * bpffs pin is ever created. Seed bytes never reach a diagnostic. */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct bpf_object;
struct bpf_map;
struct bpf_program;

enum {
    MAP_COUNT = 3,
    LOG_LIMIT = 8192,
    SEED_SIZE = 560,
    READY_LIMIT = 1024,
    PROGRAM_LIMIT = 64,
    TASK_LIMIT = 64,
    TIMEOUT_LIMIT = 60000,
    PATH_LIMIT = PATH_MAX - 64,
    POLL_NANOSECONDS = 20000000,
};

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434 /* x86-64 only fixture */
#endif

static const char *const map_names[MAP_COUNT] = {
    "TASK_COOKIE", "THREAD_OWNER", "ROOT_AFFILIATION",
};
static const uint32_t map_value_sizes[MAP_COUNT] = {8, 544, 8};
static const uint32_t seed_offsets[MAP_COUNT] = {0, 8, 552};

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

struct identity {
    uint32_t pid;
    uint32_t tid;
    uint64_t generation;
};

typedef int (*libbpf_print_fn)(int, const char *, va_list);
typedef int (*publish_fn)(const char *, const char *, const char *, size_t);

struct api {
    struct bpf_object *(*object_open_file)(const char *, const void *);
    long (*get_error)(const void *);
    struct bpf_program *(*object_next_program)(const struct bpf_object *, struct bpf_program *);
    const char *(*program_name)(const struct bpf_program *);
    int (*program_set_autoload)(struct bpf_program *, bool);
    int (*object_load)(struct bpf_object *);
    struct bpf_map *(*object_find_map)(const struct bpf_object *, const char *);
    int (*map_fd)(const struct bpf_map *);
    void (*object_close)(struct bpf_object *);
    libbpf_print_fn (*set_print)(libbpf_print_fn);
};

struct kernel_api {
    int (*info)(int, struct bpf_map_info *);
    int (*update)(int, const void *, const void *, uint64_t);
    int (*duplicate_fd)(int);
    int (*close_fd)(int);
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
    fprintf(stderr, "task-storage-canary: %s\n", message);
    return 1;
}

static bool error_pointer(const void *pointer)
{
    return (uintptr_t)pointer >= (uintptr_t)-4095;
}

static int bpf_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr attr;
    memset(info, 0, sizeof(*info));
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = (uintptr_t)info;
    return (int)syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

static int bpf_update(int fd, const void *key, const void *value, uint64_t flags)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uintptr_t)key;
    attr.value = (uintptr_t)value;
    attr.flags = flags;
    return (int)syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int duplicate_fd(int fd)
{
    return (int)fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

static int close_fd(int fd)
{
    return close(fd);
}

static int parse_u32(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;
    size_t index;
    if (!text || !*text)
        return -1;
    for (index = 0; text[index]; index++) {
        if (text[index] < '0' || text[index] > '9')
            return -1;
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno || !end || *end || parsed > UINT32_MAX)
        return -1;
    *value = (uint32_t)parsed;
    return 0;
}

static int absolute_path(const char *path)
{
    size_t length = path ? strlen(path) : 0;
    return length && length < PATH_LIMIT && path[0] == '/' ? 0 : -1;
}

static int path_absent(const char *path, const char *label)
{
    struct stat metadata;
    if (!lstat(path, &metadata)) {
        fprintf(stderr, "task-storage-canary: %s already exists: %s\n", label, path);
        return -1;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "task-storage-canary: %s lookup failed: %s: %s\n", label, path,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int read_seed(const char *path, unsigned char *seed)
{
    struct stat metadata;
    size_t used = 0;
    unsigned char extra;
    ssize_t count;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "task-storage-canary: cannot open SEED: %s: %s\n", path,
                strerror(errno));
        return -1;
    }
    if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode)) {
        close(fd);
        fail("SEED is not a regular file");
        return -1;
    }
    while (used < SEED_SIZE) {
        count = read(fd, seed + used, (size_t)SEED_SIZE - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            close(fd);
            fail("SEED read failed");
            return -1;
        }
        if (count == 0) {
            close(fd);
            fail("SEED is shorter than the fixed 560-byte layout");
            return -1;
        }
        used += (size_t)count;
    }
    for (;;) {
        count = read(fd, &extra, 1);
        if (count < 0 && errno == EINTR)
            continue;
        break;
    }
    if (count != 0) {
        close(fd);
        fail(count < 0 ? "SEED read failed" :
                         "SEED is longer than the fixed 560-byte layout");
        return -1;
    }
    if (close(fd)) {
        fail("cannot close SEED");
        return -1;
    }
    return 0;
}

static const unsigned char *seed_slice(const unsigned char *seed, size_t index)
{
    return seed + seed_offsets[index];
}

static bool info_shape_matches(const struct bpf_map_info *info, const struct map_spec *spec)
{
    size_t name_length = strlen(spec->name);
    size_t kernel_name_length = name_length < BPF_OBJ_NAME_LEN - 1 ?
        name_length : BPF_OBJ_NAME_LEN - 1;
    return info->type == BPF_MAP_TYPE_TASK_STORAGE && info->key_size == spec->key_size &&
        info->value_size == spec->value_size && info->max_entries == spec->max_entries &&
        info->map_flags == spec->map_flags &&
        !memcmp(info->name, spec->name, kernel_name_length) &&
        info->name[kernel_name_length] == 0;
}

static bool info_matches(const struct bpf_map_info *info, const struct map_spec *spec)
{
    return info->id == spec->id && info_shape_matches(info, spec);
}

static int distinct_ids(const struct map_spec specs[MAP_COUNT])
{
    size_t index, other;
    for (index = 0; index < MAP_COUNT; index++) {
        if (!specs[index].id)
            return -1;
        for (other = index + 1; other < MAP_COUNT; other++) {
            if (specs[index].id == specs[other].id)
                return -1;
        }
    }
    return 0;
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
    LOAD(api, library, object_next_program, "bpf_object__next_program");
    LOAD(api, library, program_name, "bpf_program__name");
    LOAD(api, library, program_set_autoload, "bpf_program__set_autoload");
    LOAD(api, library, object_load, "bpf_object__load");
    LOAD(api, library, object_find_map, "bpf_object__find_map_by_name");
    LOAD(api, library, map_fd, "bpf_map__fd");
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

static int write_all(int fd, const char *buffer, size_t length)
{
    while (length) {
        ssize_t written = write(fd, buffer, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return 1;
        buffer += written;
        length -= (size_t)written;
    }
    return 0;
}

static int temporary_path(const char *destination, char *output, size_t capacity)
{
    int added = snprintf(output, capacity, "%s.tmp.%ld", destination, (long)getpid());
    return added < 0 || (size_t)added >= capacity ? -1 : 0;
}

/* No-replacement publication: private temp, fsync, link, unlink, rollback. */
static int publish_private(const char *destination, const char *label,
                           const char *contents, size_t length)
{
    char temporary[PATH_MAX];
    int fd, failed, linked = 0, saved_errno;
    if (temporary_path(destination, temporary, sizeof(temporary))) {
        fprintf(stderr, "task-storage-canary: %s path is too long\n", label);
        return 1;
    }
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "task-storage-canary: %s temporary create failed: %s\n", label,
                strerror(errno));
        return 1;
    }
    failed = write_all(fd, contents, length);
    if (!failed && fsync(fd))
        failed = 1;
    if (close(fd))
        failed = 1;
    saved_errno = failed ? errno : 0;
    if (!failed && link(temporary, destination)) {
        failed = 1;
        saved_errno = errno;
    } else if (!failed) {
        linked = 1;
    }
    if (unlink(temporary)) {
        failed = 1;
        saved_errno = errno;
    }
    if (failed) {
        if (linked)
            (void)unlink(destination);
        errno = saved_errno;
        fprintf(stderr, "task-storage-canary: %s publication failed: %s\n", label,
                strerror(errno));
        return 1;
    }
    return 0;
}

static int read_generation(const char *path, uint64_t *generation)
{
    char buffer[1024];
    char *cursor, *end = NULL;
    unsigned long long parsed;
    unsigned field;
    ssize_t length;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    length = read(fd, buffer, sizeof(buffer) - 1);
    if (close(fd) && length >= 0)
        return -1;
    if (length <= 0 || (size_t)length >= sizeof(buffer))
        return -1;
    buffer[length] = '\0';
    cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ')
        return -1;
    cursor += 2;
    /* starttime is field 22, the twentieth token after the comm field. */
    for (field = 3; field < 22; field++) {
        cursor = strchr(cursor, ' ');
        if (!cursor)
            return -1;
        cursor++;
    }
    errno = 0;
    parsed = strtoull(cursor, &end, 10);
    if (errno || !parsed || !end || (*end != ' ' && *end != '\n'))
        return -1;
    *generation = (uint64_t)parsed;
    return 0;
}

static int read_roster(uint32_t pid, struct identity *tasks, size_t limit, size_t *count)
{
    DIR *directory = opendir("/proc/self/task");
    struct dirent *entry;
    int failed = 0;
    *count = 0;
    if (!directory)
        return -1;
    while (!failed && (entry = readdir(directory))) {
        char path[320];
        uint32_t tid = 0;
        uint64_t generation = 0;
        int added;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (*count >= limit || parse_u32(entry->d_name, &tid) || !tid) {
            failed = 1;
            break;
        }
        added = snprintf(path, sizeof(path), "/proc/self/task/%s/stat", entry->d_name);
        if (added < 0 || (size_t)added >= sizeof(path) ||
            read_generation(path, &generation)) {
            failed = 1;
            break;
        }
        tasks[*count].pid = pid;
        tasks[*count].tid = tid;
        tasks[*count].generation = generation;
        (*count)++;
    }
    if (closedir(directory))
        failed = 1;
    return failed ? -1 : 0;
}

static int read_identity(struct identity *identity, struct identity *tasks, size_t limit,
                         size_t *count)
{
    identity->pid = (uint32_t)getpid();
    identity->tid = (uint32_t)syscall(SYS_gettid);
    if (!identity->pid || !identity->tid ||
        read_generation("/proc/self/stat", &identity->generation))
        return -1;
    if (read_roster(identity->pid, tasks, limit, count))
        return -1;
    if (*count != 1 || tasks[0].tid != identity->tid ||
        tasks[0].generation != identity->generation)
        return -1;
    return 0;
}

static int render_ready(char *output, size_t capacity, const struct identity *identity,
                        const struct identity *tasks, size_t task_count,
                        const struct map_spec specs[MAP_COUNT])
{
    size_t used = 0, index;
    int added;
    if (!capacity || !task_count)
        return -1;
    added = snprintf(output, capacity,
                     "{\"schema\":\"p11scope/task-storage-canary/v1\",\"abi\":\"x86-64\","
                     "\"pid\":%lu,\"tid\":%lu,\"generation\":%llu,\"tasks\":[",
                     (unsigned long)identity->pid, (unsigned long)identity->tid,
                     (unsigned long long)identity->generation);
    if (added < 0 || (size_t)added >= capacity)
        return -1;
    used = (size_t)added;
    for (index = 0; index < task_count; index++) {
        added = snprintf(output + used, capacity - used,
                         "%s{\"pid\":%lu,\"tid\":%lu,\"generation\":%llu}",
                         index ? "," : "", (unsigned long)tasks[index].pid,
                         (unsigned long)tasks[index].tid,
                         (unsigned long long)tasks[index].generation);
        if (added < 0 || (size_t)added >= capacity - used)
            return -1;
        used += (size_t)added;
    }
    added = snprintf(output + used, capacity - used, "],\"maps\":[");
    if (added < 0 || (size_t)added >= capacity - used)
        return -1;
    used += (size_t)added;
    for (index = 0; index < MAP_COUNT; index++) {
        added = snprintf(output + used, capacity - used,
                         "%s{\"name\":\"%s\",\"id\":%lu,\"type\":\"task_storage\","
                         "\"bytes_key\":%lu,\"bytes_value\":%lu,\"max_entries\":%lu,"
                         "\"map_flags\":%lu}",
                         index ? "," : "", specs[index].name,
                         (unsigned long)specs[index].id, (unsigned long)specs[index].key_size,
                         (unsigned long)specs[index].value_size,
                         (unsigned long)specs[index].max_entries,
                         (unsigned long)specs[index].map_flags);
        if (added < 0 || (size_t)added >= capacity - used)
            return -1;
        used += (size_t)added;
    }
    added = snprintf(output + used, capacity - used, "]}\n");
    if (added < 0 || (size_t)added >= capacity - used)
        return -1;
    used += (size_t)added;
    return (int)used;
}

static int disable_autoload(const struct api *api, struct bpf_object *object)
{
    struct bpf_program *program = NULL;
    int programs = 0;
    while ((program = api->object_next_program(object, program))) {
        const char *name;
        if (error_pointer(program) || ++programs > PROGRAM_LIMIT)
            return -1;
        name = api->program_name(program);
        if (!name || error_pointer(name) || !*name)
            return -1;
        if (api->program_set_autoload(program, false))
            return -1;
    }
    return programs ? 0 : -1;
}

static int acquire_maps(const struct api *api, const struct kernel_api *kernel,
                        struct bpf_object *object, struct map_spec specs[MAP_COUNT])
{
    size_t index;
    for (index = 0; index < MAP_COUNT; index++) {
        struct bpf_map_info info;
        int borrowed;
        specs[index].map = api->object_find_map(object, specs[index].name);
        if (!specs[index].map || error_pointer(specs[index].map))
            return -1;
        borrowed = api->map_fd(specs[index].map);
        if (borrowed < 0)
            return -1;
        /* Own a duplicate: bpf_object__close still owns the object's copy. */
        specs[index].fd = kernel->duplicate_fd(borrowed);
        if (specs[index].fd < 0)
            return -1;
        if (kernel->info(specs[index].fd, &info) || !info.id ||
            !info_shape_matches(&info, &specs[index]))
            return -1;
        specs[index].id = info.id;
    }
    return distinct_ids(specs);
}

static int seed_maps(const struct kernel_api *kernel, const struct map_spec specs[MAP_COUNT],
                     const unsigned char *seed, int pidfd)
{
    uint32_t key = (uint32_t)pidfd;
    size_t index;
    if (pidfd < 0)
        return -1;
    for (index = 0; index < MAP_COUNT; index++) {
        if (specs[index].fd < 0 ||
            kernel->update(specs[index].fd, &key, seed_slice(seed, index), BPF_ANY))
            return -1;
    }
    return 0;
}

static int revalidate_maps(const struct kernel_api *kernel,
                           const struct map_spec specs[MAP_COUNT])
{
    size_t index;
    for (index = 0; index < MAP_COUNT; index++) {
        struct bpf_map_info info;
        if (kernel->info(specs[index].fd, &info) || !info_matches(&info, &specs[index]))
            return -1;
    }
    return distinct_ids(specs);
}

static void release_resources(const struct api *api, const struct kernel_api *kernel,
                              int *pidfd, struct bpf_object **object,
                              struct map_spec specs[MAP_COUNT])
{
    size_t index;
    for (index = 0; index < MAP_COUNT; index++) {
        if (specs[index].fd >= 0) {
            kernel->close_fd(specs[index].fd);
            specs[index].fd = -1;
        }
        specs[index].map = NULL;
    }
    if (*object) {
        api->object_close(*object);
        *object = NULL;
    }
    if (*pidfd >= 0) {
        kernel->close_fd(*pidfd);
        *pidfd = -1;
    }
}

static int load_seed_publish(const struct api *api, const struct kernel_api *kernel,
                             publish_fn publish, struct bpf_object *object,
                             struct map_spec specs[MAP_COUNT], const unsigned char *seed,
                             int pidfd, const struct identity *identity,
                             const struct identity *tasks, size_t task_count,
                             const char *ready, const char **stage)
{
    char document[READY_LIMIT];
    int used;
    *stage = "cannot disable autoload for every program in the BPF object";
    if (disable_autoload(api, object))
        return -1;
    *stage = "cannot load the BPF object";
    if (api->object_load(object))
        return -1;
    *stage = "cannot acquire the exact fresh task-storage maps";
    if (acquire_maps(api, kernel, object, specs))
        return -1;
    *stage = "cannot seed the task-storage cells";
    if (seed_maps(kernel, specs, seed, pidfd))
        return -1;
    *stage = "task-storage map identity or metadata changed after seeding";
    if (revalidate_maps(kernel, specs))
        return -1;
    *stage = "READY document does not fit its bound";
    used = render_ready(document, sizeof(document), identity, tasks, task_count, specs);
    if (used < 0)
        return -1;
    *stage = "cannot publish the READY document";
    if (publish(ready, "READY", document, (size_t)used))
        return -1;
    *stage = NULL;
    return 0;
}

static int wait_for_release(const char *release, uint32_t timeout_ms)
{
    uint64_t start = monotonic_millis();
    uint64_t deadline;
    if (start == UINT64_MAX)
        return -1;
    deadline = start + timeout_ms;
    for (;;) {
        struct stat metadata;
        uint64_t now;
        if (!lstat(release, &metadata))
            return 0;
        if (errno != ENOENT) {
            fprintf(stderr, "task-storage-canary: RELEASE lookup failed: %s: %s\n", release,
                    strerror(errno));
            return -1;
        }
        now = monotonic_millis();
        if (now == UINT64_MAX || now >= deadline) {
            fail("timed out waiting for RELEASE");
            return -1;
        }
        nanosleep(&(struct timespec){0, POLL_NANOSECONDS}, NULL);
    }
}

/* ---------------------------------------------------------------------------
 * Injected self-test surfaces. These fakes never touch the kernel or libbpf.
 * ------------------------------------------------------------------------ */

enum { FAKE_PROGRAMS = 2, FAKE_PIDFD = 500 };

struct lifecycle_state {
    struct map_spec *specs;
    const unsigned char *seed;
    int pidfd;
    int program_visits;
    int autoload_disable_calls;
    int autoload_enable_calls;
    int disabled_mask;
    int autoload_skip;
    int load_calls;
    int load_with_enabled_program;
    int find_calls;
    int map_fd_calls;
    int dup_calls;
    int info_calls;
    int update_calls;
    int close_calls;
    int object_close_calls;
    int publish_calls;
    int acquire_failure;
    int update_failure;
    int publish_failure;
    int substituted_reload_map;
    int after_update;
    int violations;
};

static struct lifecycle_state lifecycle;
static char published_document[READY_LIMIT];
static size_t published_length;

static const char *const fake_program_names[FAKE_PROGRAMS] = {
    "dump_task_storage", "second_program",
};

static struct bpf_program *fake_next_program(const struct bpf_object *object,
                                             struct bpf_program *previous)
{
    int index = (int)(uintptr_t)previous;
    (void)object;
    if (index >= FAKE_PROGRAMS)
        return NULL;
    lifecycle.program_visits++;
    return (struct bpf_program *)(uintptr_t)(index + 1);
}

static const char *fake_program_name(const struct bpf_program *program)
{
    int index = (int)(uintptr_t)program - 1;
    if (index < 0 || index >= FAKE_PROGRAMS)
        return NULL;
    return fake_program_names[index];
}

static int fake_set_autoload(struct bpf_program *program, bool autoload)
{
    int index = (int)(uintptr_t)program - 1;
    if (index < 0 || index >= FAKE_PROGRAMS)
        return -1;
    if (autoload) {
        lifecycle.autoload_enable_calls++;
        return -1;
    }
    if (index == lifecycle.autoload_skip)
        return 0;
    lifecycle.autoload_disable_calls++;
    lifecycle.disabled_mask |= 1 << index;
    return 0;
}

static int fake_object_load(struct bpf_object *object)
{
    (void)object;
    lifecycle.load_calls++;
    if (lifecycle.disabled_mask != (1 << FAKE_PROGRAMS) - 1) {
        lifecycle.load_with_enabled_program++;
        return -1;
    }
    return 0;
}

static struct bpf_map *fake_find_map(const struct bpf_object *object, const char *name)
{
    size_t index;
    (void)object;
    lifecycle.find_calls++;
    for (index = 0; index < MAP_COUNT; index++) {
        if (!strcmp(name, lifecycle.specs[index].name))
            return (struct bpf_map *)(uintptr_t)(index + 1);
    }
    return NULL;
}

static int fake_map_fd(const struct bpf_map *map)
{
    int index = (int)(uintptr_t)map - 1;
    lifecycle.map_fd_calls++;
    if (index < 0 || index >= MAP_COUNT)
        return -1;
    return 100 + index;
}

static int fake_duplicate(int fd)
{
    int index = fd - 100;
    if (index < 0 || index >= MAP_COUNT || index == lifecycle.acquire_failure)
        return -1;
    lifecycle.dup_calls++;
    return 200 + index;
}

static int fake_info(int fd, struct bpf_map_info *info)
{
    int index = fd - 200;
    struct map_spec *spec;
    size_t name_length;
    lifecycle.info_calls++;
    if (index < 0 || index >= MAP_COUNT)
        return -1;
    spec = &lifecycle.specs[index];
    memset(info, 0, sizeof(*info));
    info->id = spec->id;
    info->type = BPF_MAP_TYPE_TASK_STORAGE;
    info->key_size = spec->key_size;
    info->value_size = spec->value_size;
    info->max_entries = spec->max_entries;
    info->map_flags = spec->map_flags;
    name_length = strlen(spec->name);
    if (name_length >= BPF_OBJ_NAME_LEN)
        name_length = BPF_OBJ_NAME_LEN - 1;
    memcpy(info->name, spec->name, name_length);
    if (lifecycle.after_update && index == lifecycle.substituted_reload_map)
        info->id++;
    return 0;
}

static int fake_update(int fd, const void *key, const void *value, uint64_t flags)
{
    int index = fd - 200;
    lifecycle.update_calls++;
    if (index < 0 || index >= MAP_COUNT)
        return -1;
    if (!key || *(const uint32_t *)key != (uint32_t)lifecycle.pidfd ||
        value != (const void *)seed_slice(lifecycle.seed, (size_t)index) ||
        flags != BPF_ANY)
        lifecycle.violations++;
    if (lifecycle.update_calls == MAP_COUNT)
        lifecycle.after_update = 1;
    return index == lifecycle.update_failure ? -1 : 0;
}

static int fake_close(int fd)
{
    if (fd < 0) {
        lifecycle.violations++;
        return -1;
    }
    lifecycle.close_calls++;
    return 0;
}

static void fake_object_close(struct bpf_object *object)
{
    (void)object;
    lifecycle.object_close_calls++;
}

static int fake_publish(const char *destination, const char *label, const char *contents,
                        size_t length)
{
    (void)destination;
    lifecycle.publish_calls++;
    if (!label || strcmp(label, "READY") || !contents || length >= sizeof(published_document))
        lifecycle.violations++;
    else {
        memcpy(published_document, contents, length);
        published_document[length] = '\0';
        published_length = length;
    }
    return lifecycle.publish_failure ? 1 : 0;
}

static void reset_lifecycle(struct map_spec specs[MAP_COUNT], const unsigned char *seed)
{
    size_t index;
    memset(&lifecycle, 0, sizeof(lifecycle));
    memset(published_document, 0, sizeof(published_document));
    published_length = 0;
    lifecycle.specs = specs;
    lifecycle.seed = seed;
    lifecycle.pidfd = FAKE_PIDFD;
    lifecycle.autoload_skip = -1;
    lifecycle.acquire_failure = -1;
    lifecycle.update_failure = -1;
    lifecycle.substituted_reload_map = -1;
    for (index = 0; index < MAP_COUNT; index++) {
        specs[index].fd = -1;
        specs[index].map = NULL;
        specs[index].id = 40 + (uint32_t)index;
    }
}

static void injected_apis(struct api *api, struct kernel_api *kernel)
{
    memset(api, 0, sizeof(*api));
    api->object_next_program = fake_next_program;
    api->program_name = fake_program_name;
    api->program_set_autoload = fake_set_autoload;
    api->object_load = fake_object_load;
    api->object_find_map = fake_find_map;
    api->map_fd = fake_map_fd;
    api->object_close = fake_object_close;
    kernel->info = fake_info;
    kernel->update = fake_update;
    kernel->duplicate_fd = fake_duplicate;
    kernel->close_fd = fake_close;
}

static void reset_specs(struct map_spec specs[MAP_COUNT])
{
    size_t index;
    memset(specs, 0, sizeof(*specs) * MAP_COUNT);
    for (index = 0; index < MAP_COUNT; index++) {
        specs[index].name = map_names[index];
        specs[index].key_size = 4;
        specs[index].value_size = map_value_sizes[index];
        specs[index].max_entries = 0;
        specs[index].map_flags = BPF_F_NO_PREALLOC;
        specs[index].fd = -1;
    }
}

static int exact_map_self_test(void)
{
    struct map_spec specs[MAP_COUNT];
    struct bpf_map_info info;
    struct map_spec spec = {
        .name = "THREAD_OWNER", .id = 42, .key_size = 4, .value_size = 544,
        .max_entries = 0, .map_flags = BPF_F_NO_PREALLOC, .fd = -1, .map = NULL,
    };
    size_t index;
    memset(&info, 0, sizeof(info));
    info.id = 42;
    info.type = BPF_MAP_TYPE_TASK_STORAGE;
    info.key_size = 4;
    info.value_size = 544;
    info.max_entries = 0;
    info.map_flags = BPF_F_NO_PREALLOC;
    memcpy(info.name, spec.name, strlen(spec.name) + 1);
    if (!info_matches(&info, &spec))
        return fail("self-test rejected the exact created map");
    info.id++;
    if (info_matches(&info, &spec))
        return fail("self-test accepted a substituted map id");
    info.id--;
    info.value_size--;
    if (info_matches(&info, &spec))
        return fail("self-test accepted a changed value size");
    info.value_size++;
    info.map_flags = 0;
    if (info_matches(&info, &spec))
        return fail("self-test accepted changed map flags");
    info.map_flags = BPF_F_NO_PREALLOC;
    info.type = BPF_MAP_TYPE_HASH;
    if (info_matches(&info, &spec))
        return fail("self-test accepted a non task-storage map type");
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
        return fail("self-test rejected the canonical kernel-truncated map name");
    info.name[BPF_OBJ_NAME_LEN - 2] = 'X';
    if (info_matches(&info, &spec))
        return fail("self-test accepted a mutated kernel-truncated map name");
    reset_specs(specs);
    for (index = 0; index < MAP_COUNT; index++)
        specs[index].id = 40 + (uint32_t)index;
    if (distinct_ids(specs))
        return fail("self-test rejected three distinct map ids");
    specs[2].id = specs[0].id;
    if (!distinct_ids(specs))
        return fail("self-test accepted a duplicate map id");
    specs[2].id = 0;
    if (!distinct_ids(specs))
        return fail("self-test accepted a zero map id");
    puts("task-storage-canary exact-map mutation self-test: OK");
    return 0;
}

static int seed_layout_self_test(void)
{
    unsigned char seed[SEED_SIZE];
    uint32_t total = 0;
    size_t index;
    memset(seed, 0, sizeof(seed));
    for (index = 0; index < MAP_COUNT; index++) {
        if (seed_offsets[index] != total)
            return fail("self-test seed slice offset mismatch");
        if (seed_slice(seed, index) != seed + total)
            return fail("self-test seed slice pointer mismatch");
        if (total > (uint32_t)SEED_SIZE - map_value_sizes[index])
            return fail("self-test seed slice overruns the fixed layout");
        total += map_value_sizes[index];
    }
    if (total != SEED_SIZE || map_value_sizes[0] != 8 || map_value_sizes[1] != 544 ||
        map_value_sizes[2] != 8)
        return fail("self-test seed layout is not 8/544/8 over 560 bytes");
    puts("task-storage-canary seed layout self-test: OK");
    return 0;
}

static int ready_document_self_test(void)
{
    static const char expected[] =
        "{\"schema\":\"p11scope/task-storage-canary/v1\",\"abi\":\"x86-64\","
        "\"pid\":4321,\"tid\":4321,\"generation\":987654321,"
        "\"tasks\":[{\"pid\":4321,\"tid\":4321,\"generation\":987654321}],"
        "\"maps\":[{\"name\":\"TASK_COOKIE\",\"id\":40,\"type\":\"task_storage\","
        "\"bytes_key\":4,\"bytes_value\":8,\"max_entries\":0,\"map_flags\":1},"
        "{\"name\":\"THREAD_OWNER\",\"id\":41,\"type\":\"task_storage\","
        "\"bytes_key\":4,\"bytes_value\":544,\"max_entries\":0,\"map_flags\":1},"
        "{\"name\":\"ROOT_AFFILIATION\",\"id\":42,\"type\":\"task_storage\","
        "\"bytes_key\":4,\"bytes_value\":8,\"max_entries\":0,\"map_flags\":1}]}\n";
    struct identity identity = {.pid = 4321, .tid = 4321, .generation = 987654321};
    struct identity tasks[TASK_LIMIT];
    struct map_spec specs[MAP_COUNT];
    char document[READY_LIMIT];
    char destination[PATH_MAX];
    char temporary[PATH_MAX];
    size_t index;
    int used;
    reset_specs(specs);
    for (index = 0; index < MAP_COUNT; index++)
        specs[index].id = 40 + (uint32_t)index;
    for (index = 0; index < TASK_LIMIT; index++) {
        tasks[index].pid = identity.pid;
        tasks[index].tid = identity.tid;
        tasks[index].generation = identity.generation;
    }
    used = render_ready(document, sizeof(document), &identity, tasks, 1, specs);
    if (used < 0 || (size_t)used != strlen(expected) || strcmp(document, expected))
        return fail("self-test READY document does not match the frozen schema");
    if (render_ready(document, sizeof(document), &identity, tasks, TASK_LIMIT, specs) >= 0)
        return fail("self-test accepted an over-long READY roster");
    if (render_ready(document, 64, &identity, tasks, 1, specs) >= 0)
        return fail("self-test truncated the READY document instead of refusing");
    if (render_ready(document, (size_t)used, &identity, tasks, 1, specs) >= 0)
        return fail("self-test truncated the READY document at its exact bound");
    if (render_ready(document, (size_t)used + 1, &identity, tasks, 1, specs) != used)
        return fail("self-test rejected an exactly fitting READY document");
    if (render_ready(document, sizeof(document), &identity, tasks, 0, specs) >= 0)
        return fail("self-test accepted an empty READY roster");
    memset(destination, 'p', sizeof(destination) - 1);
    destination[0] = '/';
    destination[sizeof(destination) - 1] = '\0';
    if (!temporary_path(destination, temporary, sizeof(temporary)))
        return fail("self-test accepted an over-long publication path");
    if (temporary_path("/tmp/ready.json", temporary, sizeof(temporary)) ||
        strncmp(temporary, "/tmp/ready.json.tmp.", 20))
        return fail("self-test private temporary path mismatch");
    puts("task-storage-canary READY document self-test: OK");
    return 0;
}

static int check_counters(const char *label, int expect_dup, int expect_update,
                          int expect_publish, int expect_close)
{
    if (lifecycle.violations)
        return fail(label);
    if (lifecycle.dup_calls != expect_dup || lifecycle.update_calls != expect_update ||
        lifecycle.publish_calls != expect_publish || lifecycle.close_calls != expect_close ||
        lifecycle.object_close_calls != 1 || lifecycle.autoload_enable_calls ||
        lifecycle.load_calls > 1)
        return fail(label);
    return 0;
}

static int lifecycle_self_test(void)
{
    struct map_spec specs[MAP_COUNT];
    struct identity identity = {.pid = 4321, .tid = 4321, .generation = 987654321};
    struct identity tasks[1];
    unsigned char seed[SEED_SIZE];
    struct api api;
    struct kernel_api kernel;
    struct bpf_object *object;
    const char *stage = NULL;
    int pidfd;
    size_t index;
    injected_apis(&api, &kernel);
    memset(seed, 0x5a, sizeof(seed));
    tasks[0] = identity;

    /* Exact injected lifecycle: every program disabled, three maps, one publish. */
    reset_specs(specs);
    reset_lifecycle(specs, seed);
    object = (struct bpf_object *)(uintptr_t)1;
    pidfd = FAKE_PIDFD;
    if (load_seed_publish(&api, &kernel, fake_publish, object, specs, seed, pidfd, &identity,
                          tasks, 1, "/dev/null", &stage))
        return fail("self-test rejected the exact injected seed lifecycle");
    if (lifecycle.program_visits != FAKE_PROGRAMS ||
        lifecycle.autoload_disable_calls != FAKE_PROGRAMS || lifecycle.load_calls != 1 ||
        lifecycle.load_with_enabled_program || lifecycle.info_calls != 2 * MAP_COUNT ||
        stage)
        return fail("self-test injected lifecycle sequence mismatch");
    if (published_length != strlen(published_document) || published_length < 400)
        return fail("self-test injected publication mismatch");
    release_resources(&api, &kernel, &pidfd, &object, specs);
    if (check_counters("self-test exact lifecycle cleanup mismatch", MAP_COUNT, MAP_COUNT, 1,
                       MAP_COUNT + 1))
        return 1;
    for (index = 0; index < MAP_COUNT; index++) {
        if (specs[index].fd != -1 || specs[index].map)
            return fail("self-test left a map resource open");
    }
    if (pidfd != -1 || object)
        return fail("self-test left the pidfd or object open");

    /* A program left enabled must stop the lifecycle before any map is acquired. */
    reset_specs(specs);
    reset_lifecycle(specs, seed);
    lifecycle.autoload_skip = 0;
    object = (struct bpf_object *)(uintptr_t)1;
    pidfd = FAKE_PIDFD;
    if (!load_seed_publish(&api, &kernel, fake_publish, object, specs, seed, pidfd, &identity,
                           tasks, 1, "/dev/null", &stage))
        return fail("self-test loaded an object with an enabled program");
    release_resources(&api, &kernel, &pidfd, &object, specs);
    if (!lifecycle.load_with_enabled_program || lifecycle.find_calls ||
        check_counters("self-test enabled-program cleanup mismatch", 0, 0, 0, 1))
        return 1;

    /* Partial acquisition: only the acquired duplicate and the pidfd are closed. */
    reset_specs(specs);
    reset_lifecycle(specs, seed);
    lifecycle.acquire_failure = 1;
    object = (struct bpf_object *)(uintptr_t)1;
    pidfd = FAKE_PIDFD;
    if (!load_seed_publish(&api, &kernel, fake_publish, object, specs, seed, pidfd, &identity,
                           tasks, 1, "/dev/null", &stage))
        return fail("self-test accepted partial map acquisition");
    release_resources(&api, &kernel, &pidfd, &object, specs);
    if (lifecycle.find_calls != 2 || lifecycle.map_fd_calls != 2 ||
        check_counters("self-test partial-acquisition cleanup mismatch", 1, 0, 0, 2))
        return 1;

    /* Update failure: nothing is published and every duplicate is closed once. */
    reset_specs(specs);
    reset_lifecycle(specs, seed);
    lifecycle.update_failure = 1;
    object = (struct bpf_object *)(uintptr_t)1;
    pidfd = FAKE_PIDFD;
    if (!load_seed_publish(&api, &kernel, fake_publish, object, specs, seed, pidfd, &identity,
                           tasks, 1, "/dev/null", &stage))
        return fail("self-test accepted a failed map update");
    release_resources(&api, &kernel, &pidfd, &object, specs);
    if (published_length ||
        check_counters("self-test update-failure cleanup mismatch", MAP_COUNT, 2, 0,
                       MAP_COUNT + 1))
        return 1;

    /* A substituted id after seeding is refused before publication. */
    reset_specs(specs);
    reset_lifecycle(specs, seed);
    lifecycle.substituted_reload_map = 1;
    object = (struct bpf_object *)(uintptr_t)1;
    pidfd = FAKE_PIDFD;
    if (!load_seed_publish(&api, &kernel, fake_publish, object, specs, seed, pidfd, &identity,
                           tasks, 1, "/dev/null", &stage))
        return fail("self-test accepted a substituted post-seed map id");
    release_resources(&api, &kernel, &pidfd, &object, specs);
    if (published_length ||
        check_counters("self-test substitution cleanup mismatch", MAP_COUNT, MAP_COUNT, 0,
                       MAP_COUNT + 1))
        return 1;

    /* Publication failure closes every acquired resource exactly once. */
    reset_specs(specs);
    reset_lifecycle(specs, seed);
    lifecycle.publish_failure = 1;
    object = (struct bpf_object *)(uintptr_t)1;
    pidfd = FAKE_PIDFD;
    if (!load_seed_publish(&api, &kernel, fake_publish, object, specs, seed, pidfd, &identity,
                           tasks, 1, "/dev/null", &stage))
        return fail("self-test accepted a failed READY publication");
    release_resources(&api, &kernel, &pidfd, &object, specs);
    if (check_counters("self-test publication-failure cleanup mismatch", MAP_COUNT, MAP_COUNT,
                       1, MAP_COUNT + 1))
        return 1;
    puts("task-storage-canary injected lifecycle self-test: OK");
    return 0;
}

static int self_test(void)
{
    if (exact_map_self_test() || seed_layout_self_test() || ready_document_self_test() ||
        lifecycle_self_test())
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    static const char *const labels[4] = {"OBJECT", "SEED", "READY", "RELEASE"};
    struct map_spec specs[MAP_COUNT];
    struct identity identity;
    struct identity tasks[TASK_LIMIT];
    struct api api;
    struct kernel_api kernel = {
        .info = bpf_info, .update = bpf_update, .duplicate_fd = duplicate_fd,
        .close_fd = close_fd,
    };
    unsigned char seed[SEED_SIZE];
    struct bpf_object *object = NULL;
    void *library = NULL;
    const char *stage = NULL;
    uint32_t timeout_ms = 0;
    size_t task_count = 0, index;
    int pidfd = -1;
    int status = 1;

    memset(&api, 0, sizeof(api));
    memset(seed, 0, sizeof(seed));
    memset(&identity, 0, sizeof(identity));
    memset(tasks, 0, sizeof(tasks));
    reset_specs(specs);
    if (argc == 2 && !strcmp(argv[1], "--self-test"))
        return self_test();
    if (argc != 6)
        return fail("usage: task-storage-canary OBJECT SEED READY RELEASE TIMEOUT_MS "
                    "| task-storage-canary --self-test");
    for (index = 0; index < 4; index++) {
        if (absolute_path(argv[1 + index])) {
            fprintf(stderr, "task-storage-canary: %s path must be absolute and bounded\n",
                    labels[index]);
            return 1;
        }
    }
    if (parse_u32(argv[5], &timeout_ms) || !timeout_ms || timeout_ms > TIMEOUT_LIMIT)
        return fail("TIMEOUT_MS must be a decimal in (0, 60000]");
    if (path_absent(argv[3], "READY") || path_absent(argv[4], "RELEASE"))
        return 1;
    if (read_seed(argv[2], seed))
        return 1;
    /* Every input problem is refused above, before any libbpf or BPF work. */
    pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0)
        return fail("cannot open a pidfd for this task");
    if (read_identity(&identity, tasks, TASK_LIMIT, &task_count)) {
        fail("cannot read this task identity or its single-task roster");
        goto cleanup;
    }
    library = dlopen("libbpf.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library || load_api(library, &api)) {
        fail("cannot load the required libbpf.so.1 API");
        goto cleanup;
    }
    api.set_print(bounded_libbpf_log);
    object = api.object_open_file(argv[1], NULL);
    if (!object || error_pointer(object) || api.get_error(object)) {
        object = NULL;
        fail("cannot open the BPF object");
        goto cleanup;
    }
    if (load_seed_publish(&api, &kernel, publish_private, object, specs, seed, pidfd,
                          &identity, tasks, task_count, argv[3], &stage)) {
        fail(stage ? stage : "cannot create and seed the task-storage maps");
        goto cleanup;
    }
    /* READY is published; no cell is mutated again. */
    if (wait_for_release(argv[4], timeout_ms))
        goto cleanup;
    status = 0;

cleanup:
    release_resources(&api, &kernel, &pidfd, &object, specs);
    if (library)
        dlclose(library);
    return status;
}
