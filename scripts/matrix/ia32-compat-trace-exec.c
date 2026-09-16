#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

extern char **environ;

struct sha256 {
    uint32_t state[8];
    uint64_t bytes;
    unsigned char block[64];
    size_t used;
};

static const uint32_t sha_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotate(uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
}

static void sha_block(struct sha256 *ctx, const unsigned char *block) {
    uint32_t words[64], a, b, c, d, e, f, g, h;
    for (size_t i = 0; i < 16; i++) {
        words[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t x = words[i - 15], y = words[i - 2];
        uint32_t s0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3);
        uint32_t s1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choice + sha_k[i] + words[i];
        uint32_t s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + majority;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha_init(struct sha256 *ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bytes = 0;
    ctx->used = 0;
}

static void sha_update(struct sha256 *ctx, const unsigned char *data, size_t length) {
    ctx->bytes += length;
    while (length > 0) {
        size_t take = sizeof(ctx->block) - ctx->used;
        if (take > length) take = length;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        length -= take;
        if (ctx->used == sizeof(ctx->block)) {
            sha_block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

static void sha_finish(struct sha256 *ctx, unsigned char digest[32]) {
    uint64_t bits = ctx->bytes * 8;
    ctx->block[ctx->used++] = 0x80;
    if (ctx->used > 56) {
        memset(ctx->block + ctx->used, 0, 64 - ctx->used);
        sha_block(ctx, ctx->block);
        ctx->used = 0;
    }
    memset(ctx->block + ctx->used, 0, 56 - ctx->used);
    for (size_t i = 0; i < 8; i++) ctx->block[63 - i] = (unsigned char)(bits >> (i * 8));
    sha_block(ctx, ctx->block);
    for (size_t i = 0; i < 8; i++) {
        digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)ctx->state[i];
    }
}

static void fail(const char *message) {
    fprintf(stderr, "ia32 trace exec: %s\n", message);
    exit(2);
}

static void fail_errno(const char *message) {
    fprintf(stderr, "ia32 trace exec: %s: %s\n", message, strerror(errno));
    exit(2);
}

static unsigned long long positive(const char *text, const char **end) {
    char *parsed;
    unsigned long long value;
    errno = 0;
    value = strtoull(text, &parsed, 10);
    if (errno != 0 || parsed == text || value == 0) fail("invalid identity integer");
    *end = parsed;
    return value;
}

static void read_identity(const char *path, pid_t *pid, unsigned long long *starttime) {
    char buffer[128];
    const char *cursor;
    unsigned long long raw_pid;
    struct stat facts;
    ssize_t size;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail_errno("open parent identity");
    if (fstat(fd, &facts) != 0) fail_errno("stat parent identity");
    if (!S_ISREG(facts.st_mode) || facts.st_uid != geteuid() || (facts.st_mode & 0777) != 0600 || facts.st_nlink != 1)
        fail("untrusted parent identity custody");
    size = read(fd, buffer, sizeof(buffer));
    if (size < 0) fail_errno("read parent identity");
    if (size == 0 || size == (ssize_t)sizeof(buffer)) fail("invalid parent identity length");
    if (read(fd, buffer, 1) != 0) fail("oversized parent identity");
    if (close(fd) != 0) fail_errno("close parent identity");
    buffer[size] = '\0';
    raw_pid = positive(buffer, &cursor);
    if (raw_pid > INT_MAX) fail("parent PID is out of range");
    *pid = (pid_t)raw_pid;
    if (*cursor++ != ' ') fail("invalid parent identity separator");
    *starttime = positive(cursor, &cursor);
    if (strcmp(cursor, "\n") != 0) fail("invalid parent identity terminator");
}

static unsigned long long proc_starttime(pid_t pid) {
    char path[64], buffer[4096], *tail, *save = NULL, *field;
    ssize_t size;
    int fd;
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >= (int)sizeof(path)) fail("parent PID is too long");
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail_errno("open parent stat");
    size = read(fd, buffer, sizeof(buffer) - 1);
    if (size <= 0) fail_errno("read parent stat");
    if (close(fd) != 0) fail_errno("close parent stat");
    buffer[size] = '\0';
    tail = strrchr(buffer, ')');
    if (tail == NULL || tail[1] != ' ') fail("malformed parent stat");
    tail += 2;
    for (int index = 0; index <= 19; index++) {
        field = strtok_r(index == 0 ? tail : NULL, " ", &save);
        if (field == NULL) fail("short parent stat");
    }
    return positive(field, (const char **)&tail);
}

static void verify_parent(pid_t expected_pid, unsigned long long expected_starttime) {
    if (getppid() != expected_pid) fail("authenticated parent is no longer current");
    if (proc_starttime(expected_pid) != expected_starttime) fail("authenticated parent generation changed");
}

static void hash_fd(int fd, char output[65]) {
    struct sha256 ctx;
    unsigned char buffer[16384], digest[32];
    ssize_t size;
    static const char digits[] = "0123456789abcdef";
    if (lseek(fd, 0, SEEK_SET) < 0) fail_errno("seek tracer executable");
    sha_init(&ctx);
    while ((size = read(fd, buffer, sizeof(buffer))) > 0) sha_update(&ctx, buffer, (size_t)size);
    if (size < 0) fail_errno("hash tracer executable");
    sha_finish(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        output[i * 2] = digits[digest[i] >> 4];
        output[i * 2 + 1] = digits[digest[i] & 15];
    }
    output[64] = '\0';
}

static void publish(const char *path, const char *content) {
    char directory[4096], *slash;
    size_t length = strlen(content), written = 0;
    int directory_fd, fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail_errno("publish guard record");
    while (written < length) {
        ssize_t amount = write(fd, content + written, length - written);
        if (amount <= 0) fail_errno("write guard record");
        written += (size_t)amount;
    }
    if (fsync(fd) != 0 || close(fd) != 0) fail_errno("sync guard record");
    if (strlen(path) >= sizeof(directory)) fail("guard record path is too long");
    strcpy(directory, path);
    slash = strrchr(directory, '/');
    if (slash == NULL) strcpy(directory, ".");
    else if (slash == directory) slash[1] = '\0';
    else *slash = '\0';
    directory_fd = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (directory_fd < 0 || fsync(directory_fd) != 0 || close(directory_fd) != 0)
        fail_errno("sync guard record directory");
}

int main(int argc, char **argv) {
    pid_t parent_pid;
    unsigned long long parent_starttime, self_starttime;
    struct stat executable;
    unsigned char capability[256];
    char digest[65], identity[128], metadata_path[4096], metadata[1024];
    int parent_fd, executable_fd;
    char *const exec_argv[] = { argv[3], "-kk", "-q", "-B", "line", argv[4], NULL };

    if (argc != 5) fail("usage: PARENT_IDENTITY SELF_IDENTITY BPFTRACE PROGRAM");
    if (getuid() != geteuid() || getgid() != getegid()) fail("credential-changing invocation is unsupported");
    read_identity(argv[1], &parent_pid, &parent_starttime);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) fail_errno("set parent-death signal");
    verify_parent(parent_pid, parent_starttime);
    parent_fd = (int)syscall(SYS_pidfd_open, parent_pid, 0);
    if (parent_fd < 0) fail_errno("open authenticated parent pidfd");

    executable_fd = open(argv[3], O_RDONLY | O_NOFOLLOW);
    if (executable_fd < 0) fail_errno("open tracer executable");
    if (fstat(executable_fd, &executable) != 0) fail_errno("stat tracer executable");
    if (!S_ISREG(executable.st_mode) || (executable.st_mode & 0111) == 0) fail("tracer target is not an executable regular file");
    if ((executable.st_mode & (S_ISUID | S_ISGID)) != 0) fail("set-ID tracer target is unsupported");
    errno = 0;
    if (fgetxattr(executable_fd, "security.capability", capability, sizeof(capability)) >= 0 || errno != ENODATA)
        fail("capability-bearing or uncheckable tracer target is unsupported");
    hash_fd(executable_fd, digest);
    self_starttime = proc_starttime(getpid());
    if (snprintf(metadata_path, sizeof(metadata_path), "%s.exec", argv[2]) >= (int)sizeof(metadata_path)) fail("guard metadata path is too long");
    if (snprintf(metadata, sizeof(metadata), "device=%llu\ninode=%llu\nsize=%llu\nsha256=%s\n",
                 (unsigned long long)executable.st_dev, (unsigned long long)executable.st_ino,
                 (unsigned long long)executable.st_size, digest) >= (int)sizeof(metadata)) fail("guard metadata is too long");
    publish(metadata_path, metadata);
    if (snprintf(identity, sizeof(identity), "%ld %llu\n", (long)getpid(), self_starttime) >= (int)sizeof(identity)) fail("guard identity is too long");
    publish(argv[2], identity);
    verify_parent(parent_pid, parent_starttime);
    if (close(parent_fd) != 0) fail_errno("close parent pidfd");
    fexecve(executable_fd, exec_argv, environ);
    fail_errno("exec pinned tracer executable");
}
