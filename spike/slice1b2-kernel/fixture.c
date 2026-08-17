#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PROBE_TARGET __attribute__((noinline, used, visibility("default")))

struct spike_function_list {
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t padding[6];
    uint64_t pointers[104];
};

struct spike_interface {
    uint64_t name;
    uint64_t function_list;
    uint64_t flags;
};

_Static_assert(offsetof(struct spike_function_list, pointers) == 8,
               "first table pointer must be at offset 8");
_Static_assert(sizeof(struct spike_function_list) == 840,
               "3.2 table fixture must end after 104 pointers");
_Static_assert(sizeof(struct spike_interface) == 24,
               "interface fixture ABI must be 24 bytes");

PROBE_TARGET void spike_pointer_target(void) {
    __asm__ __volatile__("" ::: "memory");
}

PROBE_TARGET uint64_t spike_get_function_list(uint64_t *output_pointer) {
    __asm__ __volatile__("" ::: "memory");
    (void)output_pointer;
    return 0;
}

PROBE_TARGET uint64_t spike_get_interface_list(struct spike_interface *interfaces,
                                                uint64_t *count) {
    __asm__ __volatile__("" ::: "memory");
    (void)interfaces;
    (void)count;
    return 0;
}

PROBE_TARGET void spike_stop_hook(void) {
    __asm__ __volatile__("" ::: "memory");
}

PROBE_TARGET void spike_late_target(void) {
    __asm__ __volatile__("" ::: "memory");
}

struct protected_pages {
    uint8_t *base;
    size_t page_size;
};

static struct protected_pages protected_pages_new(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        perror("sysconf");
        exit(1);
    }
    void *base = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    if (mprotect((uint8_t *)base + page_size, (size_t)page_size, PROT_NONE) != 0) {
        perror("mprotect");
        exit(1);
    }
    return (struct protected_pages){.base = base, .page_size = (size_t)page_size};
}

static void protected_pages_drop(struct protected_pages pages) {
    if (munmap(pages.base, pages.page_size * 2) != 0) {
        perror("munmap");
        exit(1);
    }
}

static struct spike_function_list *table_at(struct protected_pages pages, size_t bytes) {
    struct spike_function_list *table =
        (struct spike_function_list *)(pages.base + pages.page_size - bytes);
    memset(table, 0, bytes);
    table->version_major = 3;
    table->version_minor = 2;
    size_t pointer_count = (bytes - offsetof(struct spike_function_list, pointers)) /
                           sizeof(table->pointers[0]);
    for (size_t index = 0; index < pointer_count; index++) {
        table->pointers[index] = (uint64_t)(uintptr_t)&spike_pointer_target;
    }
    return table;
}

static void escape_pointer(const void *pointer) {
    __asm__ __volatile__("" : : "r"(pointer) : "memory");
}

static void run_function_case(size_t readable_bytes, int unreadable_table,
                              int unreadable_output_pointer) {
    struct protected_pages pages = protected_pages_new();
    uint64_t table = unreadable_table
                         ? (uint64_t)(uintptr_t)(pages.base + pages.page_size)
                         : (uint64_t)(uintptr_t)table_at(pages, readable_bytes);
    uint64_t *output_pointer = unreadable_output_pointer
                                   ? (uint64_t *)(pages.base + pages.page_size)
                                   : &table;
    volatile uint64_t result = spike_get_function_list(output_pointer);
    escape_pointer(output_pointer);
    escape_pointer((const void *)(uintptr_t)result);
    protected_pages_drop(pages);
}

static void run_interface_case(void) {
    static const char standard_name[] = "PKCS 11";
    static const char other_name[] = "vendor";
    struct protected_pages interfaces_pages = protected_pages_new();
    struct protected_pages full_pages = protected_pages_new();
    struct protected_pages short_pages = protected_pages_new();
    struct protected_pages unreadable_name_pages = protected_pages_new();
    struct spike_function_list *full = table_at(full_pages, 840);
    struct spike_function_list *short_table = table_at(short_pages, 64);
    struct spike_interface *interfaces = (struct spike_interface *)(
        interfaces_pages.base + interfaces_pages.page_size - 16 * sizeof(*interfaces));
    memset(interfaces, 0, 16 * sizeof(*interfaces));
    for (size_t index = 0; index < 12; index++) {
        interfaces[index].name = (uint64_t)(uintptr_t)standard_name;
        interfaces[index].function_list = (uint64_t)(uintptr_t)full;
    }
    interfaces[12].name = (uint64_t)(uintptr_t)standard_name;
    interfaces[12].function_list = (uint64_t)(uintptr_t)short_table;
    interfaces[13].name = (uint64_t)(uintptr_t)other_name;
    interfaces[13].function_list = (uint64_t)(uintptr_t)full;
    interfaces[14].name = 0;
    interfaces[14].function_list = (uint64_t)(uintptr_t)full;
    interfaces[15].name =
        (uint64_t)(uintptr_t)(unreadable_name_pages.base + unreadable_name_pages.page_size);
    interfaces[15].function_list = (uint64_t)(uintptr_t)full;
    volatile uint64_t count = 17;
    volatile uint64_t result = spike_get_interface_list(interfaces, (uint64_t *)&count);
    escape_pointer(interfaces);
    escape_pointer((const void *)(uintptr_t)result);
    protected_pages_drop(unreadable_name_pages);
    protected_pages_drop(short_pages);
    protected_pages_drop(full_pages);
    protected_pages_drop(interfaces_pages);
}

static void write_byte(int fd, char byte) {
    for (;;) {
        ssize_t written = write(fd, &byte, 1);
        if (written == 1) {
            return;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        perror("write");
        exit(1);
    }
}

static void read_byte(int fd) {
    char byte;
    for (;;) {
        ssize_t read_count = read(fd, &byte, 1);
        if (read_count == 1) {
            return;
        }
        if (read_count < 0 && errno == EINTR) {
            continue;
        }
        fputs("release pipe closed before one byte\n", stderr);
        exit(1);
    }
}

struct worker_args {
    int ready;
    int release;
};

static void *worker_main(void *opaque) {
    struct worker_args *args = opaque;
    write_byte(args->ready, 'W');
    struct pollfd pollfd = {.fd = args->release, .events = POLLIN, .revents = 0};
    while (poll(&pollfd, 1, -1) < 0) {
        if (errno != EINTR) {
            perror("poll");
            return (void *)1;
        }
    }
    read_byte(args->release);
    return NULL;
}

static void run_signal_case(int release_fd, int fixture_ready_fd, int marker_fd) {
    int worker_ready[2];
    int worker_release[2];
    if (pipe(worker_ready) != 0 || pipe(worker_release) != 0) {
        perror("pipe");
        exit(1);
    }
    struct worker_args args = {.ready = worker_ready[1], .release = worker_release[0]};
    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_main, &args) != 0) {
        fputs("pthread_create failed\n", stderr);
        exit(1);
    }
    read_byte(worker_ready[0]);
    write_byte(fixture_ready_fd, 'R');
    read_byte(release_fd);
    spike_stop_hook();
    write_byte(marker_fd, 'M');
    spike_late_target();
    write_byte(worker_release[1], 'X');
    void *worker_result = NULL;
    if (pthread_join(worker, &worker_result) != 0 || worker_result != NULL) {
        fputs("worker failed\n", stderr);
        exit(1);
    }
    close(worker_release[0]);
    close(worker_release[1]);
    close(worker_ready[0]);
    close(worker_ready[1]);
}

static void self_check(void) {
    run_function_case(840, 0, 0);
    run_function_case(64, 0, 0);
    run_function_case(840, 1, 0);
    run_function_case(840, 0, 1);
    run_interface_case();

    int release[2];
    int ready[2];
    int marker[2];
    if (pipe(release) != 0 || pipe(ready) != 0 || pipe(marker) != 0) {
        perror("pipe");
        exit(1);
    }
    write_byte(release[1], 'X');
    run_signal_case(release[0], ready[1], marker[1]);
    read_byte(ready[0]);
    read_byte(marker[0]);
    puts("fixture-self-check: OK");
}

static int parse_fd(const char *text) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 || value > INT32_MAX) {
        fputs("invalid file descriptor\n", stderr);
        exit(2);
    }
    return (int)value;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-check") == 0) {
        self_check();
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--signal") == 0) {
        run_signal_case(STDIN_FILENO, parse_fd(argv[2]), parse_fd(argv[3]));
        return 0;
    }
    fputs("usage: fixture {--self-check|--signal READY_FD MARKER_FD}\n", stderr);
    return 2;
}
