/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned catalog fixture driver: map providers, then sleep for the observer.
 *
 *   catalog-driver --ready <file> [--call] [--sleep <secs>] <provider.so>...
 *   Optional --surface FILE --control emits an independent JSONL owner,
 *   executable table-offset surface and timed calls. Stdin commands:
 *   load PATH, close PATH, call PHASE N, info PHASE N, init PHASE N,
 *   final PHASE N, quit. Real GetInfo requires a successful initialization.
 *   The target loads its own providers; it never reads observer output.
 *
 * dlopens every provider (RTLD_NOW, so constructors run — the fixture
 * application loading its providers, not the observer executing anything),
 * optionally resolves and calls each handle's C_GetFunctionList once (fills
 * lazily-populated tables like version_matrix.c), appends "READY <pid>" to
 * the ready file, then sleeps so `inspect --system` can scan this process
 * as a descendant of the observing helper.
 *
 * Exit codes: 0 ready (after sleeping), 2 usage, 3 dlopen failure, 4 the
 * --call surface failed, 5 the ready file could not be written.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef CK_RV (*get_function_list_fn)(void **);

#define MAX_PROVIDERS 256
#define MAX_OFFSETS 2048
struct provider {
    char path[PATH_MAX];
    int fd;
    void *handle;
    get_function_list_fn getter;
    void **functions;
    unsigned long offsets[MAX_OFFSETS], inode;
    unsigned major, minor;
    int count;
};
static struct provider providers[MAX_PROVIDERS];
static int provider_count;
static FILE *surface;
static unsigned long start_time;

static unsigned long monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) exit(6);
    return (unsigned long)now.tv_sec * 1000000000UL + (unsigned long)now.tv_nsec;
}

static unsigned long process_start(void) {
    char line[8192];
    FILE *file = fopen("/proc/self/stat", "r");
    if (!file || !fgets(line, sizeof line, file)) exit(6);
    fclose(file);
    char *field = strrchr(line, ')');
    if (!field) exit(6);
    field = strtok(field + 2, " ");
    for (int index = 3; index < 22 && field; index++) field = strtok(NULL, " ");
    if (!field) exit(6);
    return strtoul(field, NULL, 10);
}

static unsigned long endpoint_offset(struct provider *provider, void *function) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) exit(6);
    char line[8192], permissions[5];
    unsigned long low, high, offset, inode;
    unsigned major, minor;
    while (fgets(line, sizeof line, maps)) {
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &low, &high, permissions,
                   &offset, &major, &minor, &inode) != 7) continue;
        unsigned long address = (unsigned long)function;
        if (low <= address && address < high && permissions[2] == 'x' && inode == provider->inode) {
            if (provider->count && (major != provider->major || minor != provider->minor)) exit(6);
            provider->major = major;
            provider->minor = minor;
            fclose(maps);
            return offset + address - low;
        }
    }
    fclose(maps);
    fprintf(stderr, "catalog-driver: target is not an executable mapping of the held provider\n");
    exit(6);
}

static void append_table(struct provider *provider, void *table) {
    unsigned char *version = table;
    int count = version[0] == 2 && version[1] == 40 ? 68 :
                version[0] == 3 && version[1] == 0 ? 92 :
                version[0] == 3 && version[1] == 1 ? 94 :
                version[0] == 3 && version[1] == 2 ? 104 : 0;
    if (!count || provider->count + count > MAX_OFFSETS) exit(6);
    void **functions = (void **)((char *)table + 8);
    for (int index = 0; index < count; index++) {
        if (!functions[index]) continue;
        unsigned long offset = endpoint_offset(provider, functions[index]);
        provider->offsets[provider->count++] = offset;
    }
}

static void load_provider(const char *path) {
    if (provider_count == MAX_PROVIDERS || strpbrk(path, " \t\r\n\"\\")) exit(6);
    struct provider *provider = &providers[provider_count++];
    if (strlen(path) >= sizeof provider->path) exit(6);
    strcpy(provider->path, path);
    provider->fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat info;
    if (provider->fd < 0 || fstat(provider->fd, &info) || !S_ISREG(info.st_mode)) exit(6);
    provider->inode = (unsigned long)info.st_ino;
    char held[64];
    snprintf(held, sizeof held, "/proc/self/fd/%d", provider->fd);
    provider->handle = dlopen(held, RTLD_NOW | RTLD_LOCAL);
    if (!provider->handle) { fprintf(stderr, "%s\n", dlerror()); exit(3); }
    provider->getter = (get_function_list_fn)dlsym(provider->handle, "C_GetFunctionList");
    void *table = dlsym(provider->handle, "p11scope_capacity_table");
    if (!provider->getter || (!table && provider->getter(&table)) || !table) exit(4);
    provider->functions = (void **)((char *)table + 8);
    append_table(provider, table);
    /* Every standard acquisition export is a discoverable physical target.
     * Capacity-only matrices remove the unused interface exports entirely. */
    const char *names[] = {"C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface"};
    for (int index = 0; index < 3; index++) {
        void *symbol = dlsym(provider->handle, names[index]);
        if (!symbol) continue;
        unsigned long offset = endpoint_offset(provider, symbol);
        int exists = 0;
        for (int other = 0; other < provider->count; other++) exists |= provider->offsets[other] == offset;
        if (!exists) {
            if (provider->count == MAX_OFFSETS) exit(6);
            provider->offsets[provider->count++] = offset;
        }
    }
    typedef struct { char *name; void *table; unsigned long flags; } Interface;
    typedef CK_RV (*interface_list_fn)(Interface *, unsigned long *);
    interface_list_fn interfaces = (interface_list_fn)dlsym(provider->handle, "C_GetInterfaceList");
    if (interfaces) {
        unsigned long count = 0;
        if (interfaces(NULL, &count) || count > 16) exit(6);
        Interface entries[16];
        if (count && interfaces(entries, &count)) exit(6);
        for (unsigned long index = 0; index < count; index++) {
            if (!entries[index].name || !entries[index].table ||
                strcmp(entries[index].name, "PKCS 11")) continue;
            append_table(provider, entries[index].table);
        }
    }
    fprintf(surface, "{\"kind\":\"surface\",\"pid\":%d,\"start_time\":%lu,\"path\":\"%s\","
            "\"dev\":[%u,%u],\"ino\":%lu,\"offsets\":[", (int)getpid(), start_time,
            provider->path, provider->major, provider->minor, provider->inode);
    for (int index = 0; index < provider->count; index++)
        fprintf(surface, "%s%lu", index ? "," : "", provider->offsets[index]);
    fprintf(surface, "],\"loaded_ns\":%lu}\n", monotonic_ns());
    fflush(surface);
}

static void call_providers(const char *phase, unsigned count, int ordinal) {
    for (int index = 0; index < provider_count; index++) {
        struct provider *provider = &providers[index];
        if (!provider->handle) continue;
        CK_RV rv = 0;
        void *function = ordinal == 3 ? (void *)provider->getter : provider->functions[ordinal];
        unsigned long before = monotonic_ns();
        for (unsigned iteration = 0; iteration < count; iteration++) {
            if (ordinal == 2) {
                unsigned char info[128] = {0};
                rv |= ((CK_RV (*)(void *))function)(info);
            } else if (ordinal == 0) {
                struct { void *callbacks[4]; unsigned long flags; void *reserved; } args = {{0}, 2, NULL};
                rv |= ((CK_RV (*)(void *))function)(&args);
            } else if (ordinal == 1) {
                rv |= ((CK_RV (*)(void *))function)(NULL);
            } else {
                void *table = NULL;
                rv |= provider->getter(&table);
            }
        }
        fprintf(surface, "{\"kind\":\"call\",\"pid\":%d,\"start_time\":%lu,\"path\":\"%s\","
                "\"dev\":[%u,%u],\"ino\":%lu,\"offset\":%lu,\"phase\":\"%s\",\"n\":%u,\"rv\":%lu,\"t0\":%lu,\"t1\":%lu}\n",
                (int)getpid(), start_time, provider->path, provider->major, provider->minor,
                provider->inode, endpoint_offset(provider, function),
                phase, count, rv, before, monotonic_ns());
    }
    fflush(surface);
}

static int controlled(const char *ready_path, const char *ledger, long seconds, int argc, char **argv) {
    surface = fopen(ledger, "w");
    if (!surface) return 5;
    start_time = process_start();
    char exe[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (length < 0) return 6;
    exe[length] = 0;
    if (strpbrk(exe, "\"\\")) return 6;
    fprintf(surface, "{\"kind\":\"owner\",\"pid\":%d,\"start_time\":%lu,\"exe\":\"%s\"}\n",
            (int)getpid(), start_time, exe);
    for (int index = 0; index < argc; index++) load_provider(argv[index]);
    FILE *ready = fopen(ready_path, "a");
    if (!ready) return 5;
    fprintf(ready, "READY %d\n", (int)getpid());
    if (fclose(ready)) return 5;
    unsigned long deadline = monotonic_ns() + (unsigned long)seconds * 1000000000UL;
    unsigned commands = 0;
    while (monotonic_ns() < deadline && commands < 4096) {
        struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
        int available = poll(&input, 1, 100);
        if (available < 0) break;
        if (!available) continue;
        char command[PATH_MAX + 128], value[PATH_MAX];
        unsigned count;
        if (!fgets(command, sizeof command, stdin)) break;
        commands++;
        if (!strcmp(command, "quit\n")) break;
        if (sscanf(command, "call %4095s %u", value, &count) == 2 ||
            sscanf(command, "info %4095s %u", value, &count) == 2 ||
            sscanf(command, "init %4095s %u", value, &count) == 2 ||
            sscanf(command, "final %4095s %u", value, &count) == 2) {
            if (!count || count > 100000 || strpbrk(value, "\"\\")) return 2;
            int ordinal = command[0] == 'f' ? 1 : !strncmp(command, "init ", 5) ? 0 : command[0] == 'i' ? 2 : 3;
            call_providers(value, count, ordinal);
        } else if (sscanf(command, "load %4095s", value) == 1) {
            load_provider(value);
        } else if (sscanf(command, "close %4095s", value) == 1) {
            for (int index = 0; index < provider_count; index++) {
                struct provider *provider = &providers[index];
                if (provider->handle && !strcmp(value, provider->path)) {
                    fprintf(surface, "{\"kind\":\"unload\",\"pid\":%d,\"start_time\":%lu,"
                            "\"path\":\"%s\",\"dev\":[%u,%u],\"ino\":%lu,\"at_ns\":%lu}\n",
                            (int)getpid(), start_time, provider->path, provider->major,
                            provider->minor, provider->inode, monotonic_ns());
                    fflush(surface);
                    dlclose(provider->handle);
                    close(provider->fd);
                    provider->handle = NULL;
                }
            }
        } else return 2;
        puts("OK");
        fflush(stdout);
    }
    for (int index = 0; index < provider_count; index++) {
        if (providers[index].handle) { dlclose(providers[index].handle); close(providers[index].fd); }
    }
    return fclose(surface) ? 5 : 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s --ready <file> [--call] [--sleep <secs>] <provider.so>...\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *ready_path = NULL;
    int call = 0;
    long sleep_secs = 300;
    int first_so = 0;
    const char *ledger = NULL;
    int control = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ready") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            ready_path = argv[i];
        } else if (strcmp(argv[i], "--call") == 0) {
            call = 1;
        } else if (strcmp(argv[i], "--surface") == 0) {
            if (++i >= argc) return 2;
            ledger = argv[i];
        } else if (strcmp(argv[i], "--control") == 0) {
            control = 1;
        } else if (strcmp(argv[i], "--sleep") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            sleep_secs = strtol(argv[i], NULL, 10);
            if (sleep_secs <= 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (first_so == 0) {
            first_so = i;
        }
    }
    if (ready_path == NULL || first_so == 0) {
        usage(argv[0]);
        return 2;
    }
    if (ledger || control) {
        if (!ledger || !control || !call) return 2;
        return controlled(ready_path, ledger, sleep_secs, argc - first_so, argv + first_so);
    }

    for (int i = first_so; i < argc; i++) {
        void *handle = dlopen(argv[i], RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL) {
            fprintf(stderr, "catalog-driver: dlopen %s: %s\n", argv[i], dlerror());
            return 3;
        }
        if (call) {
            dlerror();
            void *symbol = dlsym(handle, "C_GetFunctionList");
            const char *error = dlerror();
            if (error != NULL || symbol == NULL) {
                fprintf(stderr, "catalog-driver: dlsym C_GetFunctionList in %s: %s\n",
                        argv[i], error != NULL ? error : "missing");
                return 4;
            }
            void *list = NULL;
            CK_RV rv = ((get_function_list_fn)symbol)(&list);
            if (rv != 0 || list == NULL) {
                fprintf(stderr, "catalog-driver: C_GetFunctionList in %s failed\n", argv[i]);
                return 4;
            }
        }
    }

    FILE *ready = fopen(ready_path, "a");
    if (ready == NULL) {
        fprintf(stderr, "catalog-driver: cannot write %s\n", ready_path);
        return 5;
    }
    fprintf(ready, "READY %d\n", (int)getpid());
    if (fclose(ready) != 0) {
        fprintf(stderr, "catalog-driver: cannot write %s\n", ready_path);
        return 5;
    }

    sleep((unsigned int)sleep_secs);
    return 0;
}
