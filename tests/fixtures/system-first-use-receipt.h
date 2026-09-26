/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private post-call receipt. Included only by the single-thread fixture driver. */
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>

#define RECEIPT_SIDECAR_LIMIT (2U * 1024U * 1024U)

static int receipt_arguments(const char *number, const char *nonce) {
    if (!*number || strspn(number, "0123456789") != strlen(number) ||
        strlen(nonce) != 64 || strspn(nonce, "0123456789abcdef") != 64) return -1;
    char *end;
    errno = 0;
    long value = strtol(number, &end, 10);
    if (errno || *end || value < 3 || value > INT_MAX) return -1;
    int kind = 0;
    socklen_t length = sizeof kind;
    if (getsockopt((int)value, SOL_SOCKET, SO_TYPE, &kind, &length) ||
        kind != SOCK_SEQPACKET) return -1;
    return (int)value;
}

static int write_all(int fd, const char *data, size_t length) {
    while (length) {
        ssize_t n = write(fd, data, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += n;
        length -= (size_t)n;
    }
    return 0;
}

static char *receipt_snapshot(int directory, const char *source, const char *name) {
    int out = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0) return NULL;
    int in = open(source, O_RDONLY | O_CLOEXEC);
    char *data = malloc(RECEIPT_SIDECAR_LIMIT + 2U);
    size_t used = 0;
    int failed = in < 0 || !data;
    while (!failed && used <= RECEIPT_SIDECAR_LIMIT) {
        ssize_t n = read(in, data + used, RECEIPT_SIDECAR_LIMIT + 1U - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { failed = 1; break; }
        if (!n) break;
        used += (size_t)n;
    }
    if (data && used && write_all(out, data, used)) failed = 1;
    if (in >= 0 && close(in)) failed = 1;
    if (close(out)) failed = 1;
    if (!used || used > RECEIPT_SIDECAR_LIMIT || (data && data[used - 1] != '\n')) {
        errno = EOVERFLOW;
        failed = 1;
    }
    if (failed) { free(data); return NULL; }
    data[used] = '\0';
    return data;
}

static int post_call_receipt(int channel, const char *nonce, const char *path,
                             uintptr_t address) {
    uint64_t started = now_ns();
    if (emit("receipt_started", started, "")) return -1;
    int result = -1, directory = -1, file = -1, mount_namespace = -1;
    char *before = NULL, *after = NULL, *mountinfo = NULL;
    struct stat directory_info, ns_before, ns_after;
    uint64_t birth_before = process_birth();
    directory = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
    if (directory < 0 || fstat(directory, &directory_info)) goto done;
    if (directory_info.st_uid != geteuid() || (directory_info.st_mode & 0022)) {
        errno = EPERM;
        goto done;
    }
    mount_namespace = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (mount_namespace < 0 || fstat(mount_namespace, &ns_before)) goto done;
    before = receipt_snapshot(directory, "/proc/self/maps", "maps-before");
    if (!before) goto done;
    unsigned long start = 0, end = 0;
    int matches = 0;
    for (const char *line = before; line && *line; ) {
        unsigned long low, high;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &low, &high, perms) == 3 &&
            low <= address && address < high && perms[2] == 'x') {
            start = low;
            end = high;
            matches++;
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    if (matches != 1) { errno = EINVAL; goto done; }
    char map_path[128];
    int n = snprintf(map_path, sizeof map_path, "/proc/self/map_files/%lx-%lx", start, end);
    if (n < 0 || (size_t)n >= sizeof map_path) { errno = EOVERFLOW; goto done; }
    /* No pathname fallback: this exact VMA relation is the receipt's authority. */
    file = open(map_path, O_RDONLY | O_CLOEXEC);
    if (file < 0) goto done;
    mountinfo = receipt_snapshot(directory, "/proc/self/mountinfo", "mountinfo");
    after = receipt_snapshot(directory, "/proc/self/maps", "maps-after");
    uint64_t birth_after = process_birth();
    if (!mountinfo || !after || stat("/proc/self/ns/mnt", &ns_after)) goto done;
    if (!birth_before || birth_before != birth || birth_after != birth ||
        ns_before.st_dev != namespace_identity.st_dev || ns_before.st_ino != namespace_identity.st_ino ||
        ns_after.st_dev != ns_before.st_dev || ns_after.st_ino != ns_before.st_ino) {
        errno = EINVAL;
        goto done;
    }
    uint64_t ready = now_ns();
    char packet[4096];
    n = snprintf(packet, sizeof packet,
        "{\"schema\":\"p11scope/first-use-fd-packet/v1\",\"nonce\":\"%s\","
        "\"pid\":%ld,\"birth_before\":%" PRIu64 ",\"birth_after\":%" PRIu64 ","
        "\"endpoint_address\":%" PRIuPTR ",\"mapping_start\":%lu,\"mapping_end\":%lu,"
        "\"receipt_started_ns\":%" PRIu64 ",\"receipt_ready_ns\":%" PRIu64 ","
        "\"namespace_dev_before\":[%u,%u],\"namespace_ino_before\":%ju,"
        "\"namespace_dev_after\":[%u,%u],\"namespace_ino_after\":%ju}\n",
        nonce, (long)getpid(), birth_before, birth_after, address, start, end, started, ready,
        major(ns_before.st_dev), minor(ns_before.st_dev), (uintmax_t)ns_before.st_ino,
        major(ns_after.st_dev), minor(ns_after.st_dev), (uintmax_t)ns_after.st_ino);
    if (n < 0 || (size_t)n >= sizeof packet) { errno = EOVERFLOW; goto done; }
    struct iovec vector = {packet, (size_t)n};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(2 * sizeof(int))]; } control = {0};
    struct msghdr message = {0};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof control.bytes;
    struct cmsghdr *ancillary = CMSG_FIRSTHDR(&message);
    ancillary->cmsg_level = SOL_SOCKET;
    ancillary->cmsg_type = SCM_RIGHTS;
    ancillary->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int descriptors[2] = {file, mount_namespace};
    memcpy(CMSG_DATA(ancillary), descriptors, sizeof descriptors);
    /* One attempt, no observer ACK and no wait for socket writability. */
    if (sendmsg(channel, &message, MSG_DONTWAIT | MSG_NOSIGNAL) != n) goto done;
    result = emit("receipt_sent", now_ns(), "");
done:
    if (result) perror("receipt acquisition");
    free(before);
    free(after);
    free(mountinfo);
    if (file >= 0) close(file);
    if (mount_namespace >= 0) close(mount_namespace);
    if (directory >= 0) close(directory);
    return result;
}
