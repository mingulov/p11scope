/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned task-bound reporter witness. Decoder fixtures never claim attachment. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct decoder {
    uint32_t pid;
    unsigned samples;
    const char *mode;
};

static int refuse(const char *message) {
    fprintf(stderr, "reporter-probe: %s\n", message);
    return -1;
}

static int number(const char *value, uint64_t *result) {
    char *end;
    if (!value[0] || value[0] == '-') return refuse("invalid unsigned argument");
    errno = 0;
    *result = strtoull(value, &end, 10);
    return errno || *end ? refuse("invalid unsigned argument") : 0;
}

static void ring_copy(void *output, const unsigned char *data, uint64_t size,
                      uint64_t position, size_t length) {
    size_t offset = position % size;
    size_t first = length < size - offset ? length : size - offset;
    memcpy(output, data + offset, first);
    memcpy((unsigned char *)output + first, data, length - first);
}

static int consume(struct decoder *decoder, const unsigned char *data, uint64_t size,
                   uint64_t head, uint64_t *tail) {
    if (!size || head < *tail || head - *tail > size)
        return refuse("lost/overrun/backward perf ring evidence");
    while (*tail < head) {
        struct perf_event_header header;
        uint64_t ip, timestamp;
        uint32_t ids[2];
        if (head - *tail < sizeof(header)) return refuse("partial perf header");
        ring_copy(&header, data, size, *tail, sizeof(header));
        if (header.size != 32 || header.size > head - *tail ||
            header.type != PERF_RECORD_SAMPLE)
            return refuse("lost/unknown/malformed perf record");
        ring_copy(&ip, data, size, *tail + 8, 8);
        ring_copy(ids, data, size, *tail + 16, 8);
        ring_copy(&timestamp, data, size, *tail + 24, 8);
        if (ids[0] != decoder->pid || ids[1] != decoder->pid)
            return refuse("reporter sample is not the bound observer main TID");
        if (!timestamp || !ip || ++decoder->samples != 1)
            return refuse("zero/duplicate reporter observation");
        printf("{\"kind\":\"reporter\",\"mode\":\"%s\",\"ip\":%" PRIu64
               ",\"pid\":%u,\"tid\":%u,\"t_ns\":%" PRIu64 "}\n",
               decoder->mode, ip, ids[0], ids[1], timestamp);
        fflush(stdout);
        *tail += header.size;
    }
    return 0;
}

static int decode_fixture(int argc, char **argv) {
    unsigned char data[256] = {0}, payload[257];
    uint64_t pid, tail, head;
    if (argc != 6 || number(argv[2], &pid) || !pid || pid > INT32_MAX ||
        number(argv[3], &tail) || number(argv[4], &head)) return refuse("invalid decoder arguments");
    FILE *input = fopen(argv[5], "rb");
    if (!input) return refuse("cannot open fixture input");
    size_t length = fread(payload, 1, sizeof(payload), input);
    int bad = ferror(input);
    fclose(input);
    if (bad || length > sizeof(data) || head < tail || head - tail != length)
        return refuse("invalid fixture extent");
    for (size_t i = 0; i < length; ++i) data[(tail + i) % sizeof(data)] = payload[i];
    struct decoder decoder = {(uint32_t)pid, 0, "decode_fixture"};
    if (consume(&decoder, data, sizeof(data), head, &tail)) return -1;
    printf("{\"kind\":\"final\",\"mode\":\"decode_fixture\",\"samples\":%u,\"lost\":0}\n", decoder.samples);
    return 0;
}

static int observer_identity(int fd, uint32_t pid, uint64_t birth, struct stat *held) {
    char path[80], line[4096], *cursor, *end;
    struct stat actual;
    if (fstat(fd, held) || !S_ISREG(held->st_mode)) return refuse("expected held executable regular FD");
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    if (stat(path, &actual) || held->st_dev != actual.st_dev || held->st_ino != actual.st_ino ||
        held->st_size != actual.st_size || held->st_mtim.tv_sec != actual.st_mtim.tv_sec ||
        held->st_mtim.tv_nsec != actual.st_mtim.tv_nsec)
        return refuse("observer executable differs from held executable");
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    FILE *input = fopen(path, "r");
    if (!input) return refuse("cannot read bound observer birth");
    cursor = fgets(line, sizeof(line), input);
    int extra = fgetc(input);
    fclose(input);
    if (!cursor || extra != EOF || !(cursor = strrchr(line, ')')))
        return refuse("invalid bound observer stat");
    cursor += 2;
    for (unsigned field = 3; field <= 22; ++field) {
        if (!*cursor) return refuse("missing bound observer birth");
        end = strchr(cursor, ' ');
        if (!end) return refuse("short bound observer stat");
        if (field == 22) {
            *end = '\0';
            uint64_t actual_birth;
            if (number(cursor, &actual_birth) || actual_birth != birth)
                return refuse("observer process birth differs");
            return 0;
        }
        cursor = end + 1;
    }
    return refuse("missing observer birth");
}

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static int probe(int argc, char **argv) {
    uint64_t exe_fd, pid, birth, offset, duration;
    struct stat held, after;
    if (argc != 7 || number(argv[2], &exe_fd) || exe_fd > INT32_MAX ||
        number(argv[3], &pid) || !pid || pid > INT32_MAX || number(argv[4], &birth) || !birth ||
        number(argv[5], &offset) || number(argv[6], &duration) || !duration || duration > 120000)
        return refuse("invalid bounded probe arguments");
    if (observer_identity((int)exe_fd, pid, birth, &held)) return -1;
    if (offset >= (uint64_t)held.st_size) return refuse("reporter offset exceeds held executable");
    unsigned type;
    FILE *input = fopen("/sys/bus/event_source/devices/uprobe/type", "r");
    if (!input) return refuse("uprobe PMU is unavailable");
    int parsed = fscanf(input, "%u", &type);
    fclose(input);
    if (parsed != 1) return refuse("invalid uprobe PMU type");
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%" PRIu64, exe_fd);
    struct perf_event_attr attr = {0};
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config1 = (uintptr_t)fd_path;
    attr.config2 = offset;
    attr.sample_period = 1;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_LOST;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.use_clockid = 1;
    attr.clockid = CLOCK_MONOTONIC;
    attr.wakeup_events = 1;
    int event = syscall(SYS_perf_event_open, &attr, (pid_t)pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (event < 0) { perror("reporter-probe: perf_event_open"); return -1; }
    long page = sysconf(_SC_PAGESIZE);
    size_t extent = page > 0 ? (size_t)page * 3 : 0;
    void *mapping = extent ? mmap(NULL, extent, PROT_READ | PROT_WRITE, MAP_SHARED, event, 0) : MAP_FAILED;
    int result = -1;
    if (mapping == MAP_FAILED) { refuse("cannot map bounded perf ring"); goto close_event; }
    struct perf_event_mmap_page *metadata = mapping;
    if (metadata->data_offset != (uint64_t)page || metadata->data_size != (uint64_t)page * 2) {
        refuse("unexpected perf ring extent"); goto unmap;
    }
    unsigned char *data = (unsigned char *)mapping + metadata->data_offset;
    if (observer_identity((int)exe_fd, pid, birth, &after) ||
        ioctl(event, PERF_EVENT_IOC_RESET, 0) || ioctl(event, PERF_EVENT_IOC_ENABLE, 0)) {
        refuse("cannot enable reporter witness for original observer"); goto unmap;
    }
    uint64_t start = monotonic_ns(), tail = 0;
    if (!start) { refuse("monotonic clock unavailable"); goto disable; }
    printf("{\"kind\":\"ready\",\"mode\":\"perf_uprobe\",\"pid\":%" PRIu64
           ",\"tid\":%" PRIu64 ",\"start_time\":%" PRIu64 ",\"dev\":%ju,\"ino\":%ju,"
           "\"file_offset\":%" PRIu64 ",\"clock\":\"CLOCK_MONOTONIC\",\"t_ns\":%" PRIu64 "}\n",
           pid, pid, birth, (uintmax_t)held.st_dev, (uintmax_t)held.st_ino, offset, start);
    fflush(stdout);
    struct decoder decoder = {(uint32_t)pid, 0, "perf_uprobe"};
    int event_hup = 0;
    for (;;) {
        struct pollfd polling[] = {{event_hup ? -1 : event, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};
        uint64_t now = monotonic_ns();
        if (!now || now < start || now - start > duration * 1000000) {
            refuse("bounded probe expired before owned stop"); goto disable;
        }
        if (poll(polling, 2, 20) < 0) {
            if (errno == EINTR) continue;
            refuse("perf witness poll failed"); goto disable;
        }
        uint64_t head = __atomic_load_n(&metadata->data_head, __ATOMIC_ACQUIRE);
        if (consume(&decoder, data, metadata->data_size, head, &tail)) goto disable;
        __atomic_store_n(&metadata->data_tail, tail, __ATOMIC_RELEASE);
        if (polling[0].revents & (POLLERR | POLLNVAL)) {
            refuse("perf witness descriptor failed"); goto disable;
        }
        /* The parent retains original custody through ready; task exit may
         * hang up this task-bound event. Still require its explicit stop and
         * reconcile final kernel counters; never treat HUP as an ACK. */
        if (polling[0].revents & POLLHUP) event_hup = 1;
        if (polling[1].revents) {
            char stop[16];
            ssize_t length = read(STDIN_FILENO, stop, sizeof(stop));
            if (length != 5 || memcmp(stop, "stop\n", 5)) {
                refuse("expected explicit bounded owned stop"); goto disable;
            }
            if (ioctl(event, PERF_EVENT_IOC_DISABLE, 0)) {
                refuse("cannot disable reporter witness"); goto disable;
            }
            head = __atomic_load_n(&metadata->data_head, __ATOMIC_ACQUIRE);
            if (consume(&decoder, data, metadata->data_size, head, &tail)) goto disable;
            __atomic_store_n(&metadata->data_tail, tail, __ATOMIC_RELEASE);
            uint64_t counters[4];
            if (read(event, counters, sizeof(counters)) != sizeof(counters) ||
                counters[0] != decoder.samples || !counters[1] || counters[1] != counters[2] || counters[3]) {
                refuse("kernel event/sample/loss/enabled counters disagree"); goto disable;
            }
            printf("{\"kind\":\"final\",\"mode\":\"perf_uprobe\",\"samples\":%u,\"lost\":0,"
                   "\"kernel_count\":%" PRIu64 ",\"time_enabled\":%" PRIu64 ",\"time_running\":%" PRIu64 "}\n",
                   decoder.samples, counters[0], counters[1], counters[2]);
            fflush(stdout);
            result = 0;
            goto unmap;
        }
    }
disable:
    (void)ioctl(event, PERF_EVENT_IOC_DISABLE, 0);
unmap:
    munmap(mapping, extent);
close_event:
    close(event);
    return result;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--decode-fixture")) return decode_fixture(argc, argv) ? 2 : 0;
    if (argc > 1 && !strcmp(argv[1], "--probe")) return probe(argc, argv) ? 2 : 0;
    return refuse("use --probe EXE_FD PID BIRTH FILE_OFFSET LIMIT_MS or --decode-fixture") ? 2 : 0;
}
