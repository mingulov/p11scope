/* SPDX-License-Identifier: GPL-3.0-or-later */
/* H6 ia32 leader exec only. Build -m32, optionally -DH6_IA32_PROVIDER
 * -shared -fPIC, or -DIA32_IMAGE=1 for the distinct successor executable.
 * Every real API call is ledgered. Initial readiness precedes calls; old
 * setup waits for G and successor setup precedes its ready barrier. Neither
 * image calls the getter or seeds any observer state. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if !defined(__i386__) || defined(__x86_64__)
#error "H6 ia32 requires ELF32 EM_386, never LP64 or x32"
#endif
typedef unsigned long CK_RV, CK_ULONG, CK_SESSION_HANDLE;
typedef struct { CK_ULONG slot, state, flags, error; } CK_SESSION_INFO;
_Static_assert(sizeof(void *) == 4 && sizeof(CK_ULONG) == 4, "ia32 ABI");
extern char **environ;

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(90);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t phase_end(uint64_t leg, uint64_t milliseconds) {
    uint64_t end = now_ns() + milliseconds * UINT64_C(1000000);
    return end < leg ? end : leg;
}
static char command(uint64_t deadline) {
    for (;;) {
        uint64_t now = now_ns();
        if (now >= deadline) _exit(92);
        uint64_t left = (deadline - now + 999999) / 1000000;
        struct pollfd p = {STDIN_FILENO, POLLIN, 0};
        int ready = poll(&p, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (ready < 0 && errno == EINTR) continue;
        if (!ready) continue;
        if (ready < 0 || (p.revents & (POLLERR | POLLNVAL)) || now_ns() >= deadline) _exit(93);
        char byte;
        ssize_t n = read(STDIN_FILENO, &byte, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n != 1 || now_ns() >= deadline) _exit(94);
        return byte;
    }
}
static void require(char want, uint64_t deadline) {
    if (command(deadline) != want) _exit(94);
}
static void quoted(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static void header(uint64_t *sequence, unsigned image, const char *kind) {
    if (*sequence == UINT64_MAX) _exit(95);
    printf("N3LEDGER {\"kind\":\"%s\",\"seq\":%" PRIu64 ",\"image\":%u,\"pid\":%d,\"tid\":%ld",
           kind, ++*sequence, image, getpid(), syscall(SYS_gettid));
}
static void end_row(void) { puts("}"); if (fflush(stdout)) _exit(96); }
static void ack(uint64_t *seq, unsigned image, const char *phase) {
    header(seq, image, "ack"); printf(",\"phase\":"); quoted(phase);
    printf(",\"t\":%" PRIu64, now_ns()); end_row();
}

struct request {
    CK_RV rv;
    int held, failed;
    unsigned image;
    uint64_t *sequence;
    uint64_t t0, leg, deadline, measurement_ms, post_deadline;
    const char *exec_path;
    char **exec_argv;
    char *next_sequence;
    uint64_t birth;
};

#ifdef H6_IA32_PROVIDER
__attribute__((noinline, visibility("default")))
CK_RV C_Initialize(void *argument) {
    struct request *r = argument;
    if (!r) return 5;
    if (r->held) {
        header(r->sequence, r->image, "held");
        printf(",\"fn\":\"C_Initialize\",\"vaddr\":%" PRIu64 ",\"t0\":%" PRIu64 ",\"t\":%" PRIu64,
               (uint64_t)(uintptr_t)&C_Initialize, r->t0, now_ns()); end_row();
        ack(r->sequence, r->image, "held");
        require('X', r->deadline);
        header(r->sequence, r->image, "exec");
        printf(",\"mode\":\"leader\",\"scope\":\"selected\",\"start_time\":%" PRIu64 ",\"path\":", r->birth);
        quoted(r->exec_path); printf(",\"t\":%" PRIu64, now_ns()); end_row();
        snprintf(r->next_sequence, 32, "%" PRIu64, *r->sequence);
        execve(r->exec_path, r->exec_argv, environ);
        int error = errno;
        if (!r->failed || error != ENOENT) _exit(97);
        header(r->sequence, r->image, "failed-exec");
        printf(",\"errno\":%d,\"path\":", error); quoted(r->exec_path);
        printf(",\"t\":%" PRIu64, now_ns()); end_row();
        ack(r->sequence, r->image, "failed-exec");
        r->post_deadline = phase_end(r->leg, r->measurement_ms);
        require('R', r->post_deadline);
    }
    return r->rv;
}
__attribute__((noinline, visibility("default")))
CK_RV C_GetInfo(void *info) { (void)info; return 0; }
static int session_open;
__attribute__((noinline, visibility("default")))
CK_RV C_OpenSession(CK_ULONG slot, CK_ULONG flags, void *application, void *notify,
                   CK_SESSION_HANDLE *session) {
    (void)flags; (void)application; (void)notify;
    if (slot != 1 || !session) return 5;
    *session = 1; session_open = 1; return 0;
}
__attribute__((noinline, visibility("default")))
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO *info) {
    static unsigned calls;
    if (!session_open || session != 1 || !info) return 5;
    *info = (CK_SESSION_INFO){1, 0, 0, 0};
    return (calls++ % 2) ? 5 : 0;
}
/* Complete canonical 2.40 list: distinct endpoints, naturally aligned at4.
 * Stubs return distinct constants so compiler folding cannot merge them. */
#define STUBS \
    Y(C_Finalize, 1) \
    Y(C_GetSlotList, 4) Y(C_GetSlotInfo, 5) Y(C_GetTokenInfo, 6) \
    Y(C_GetMechanismList, 7) Y(C_GetMechanismInfo, 8) \
    Y(C_InitToken, 9) Y(C_InitPIN, 10) Y(C_SetPIN, 11) \
    Y(C_CloseSession, 13) Y(C_CloseAllSessions, 14) \
    Y(C_GetOperationState, 16) Y(C_SetOperationState, 17) Y(C_Login, 18) Y(C_Logout, 19) \
    Y(C_CreateObject, 20) Y(C_CopyObject, 21) Y(C_DestroyObject, 22) \
    Y(C_GetObjectSize, 23) Y(C_GetAttributeValue, 24) Y(C_SetAttributeValue, 25) \
    Y(C_FindObjectsInit, 26) Y(C_FindObjects, 27) Y(C_FindObjectsFinal, 28) \
    Y(C_EncryptInit, 29) Y(C_Encrypt, 30) Y(C_EncryptUpdate, 31) Y(C_EncryptFinal, 32) \
    Y(C_DecryptInit, 33) Y(C_Decrypt, 34) Y(C_DecryptUpdate, 35) Y(C_DecryptFinal, 36) \
    Y(C_DigestInit, 37) Y(C_Digest, 38) Y(C_DigestUpdate, 39) Y(C_DigestKey, 40) Y(C_DigestFinal, 41) \
    Y(C_SignInit, 42) Y(C_Sign, 43) Y(C_SignUpdate, 44) Y(C_SignFinal, 45) \
    Y(C_SignRecoverInit, 46) Y(C_SignRecover, 47) \
    Y(C_VerifyInit, 48) Y(C_Verify, 49) Y(C_VerifyUpdate, 50) Y(C_VerifyFinal, 51) \
    Y(C_VerifyRecoverInit, 52) Y(C_VerifyRecover, 53) \
    Y(C_DigestEncryptUpdate, 54) Y(C_DecryptDigestUpdate, 55) Y(C_SignEncryptUpdate, 56) Y(C_DecryptVerifyUpdate, 57) \
    Y(C_GenerateKey, 58) Y(C_GenerateKeyPair, 59) Y(C_WrapKey, 60) Y(C_UnwrapKey, 61) Y(C_DeriveKey, 62) \
    Y(C_SeedRandom, 63) Y(C_GenerateRandom, 64) \
    Y(C_GetFunctionStatus, 65) Y(C_CancelFunction, 66) Y(C_WaitForSlotEvent, 67)
#define Y(name, n) __attribute__((noinline, visibility("default"))) CK_RV name(void) { return 0x540UL + (n); }
STUBS
#undef Y
struct function_list { unsigned char major, minor; void *functions[68]; };
_Static_assert(offsetof(struct function_list, functions) == 4, "canonical ia32 table alignment");
CK_RV C_GetFunctionList(void **list);
static struct function_list table = {2, 40, {
    [0] = (void *)&C_Initialize, [2] = (void *)&C_GetInfo,
    [3] = (void *)&C_GetFunctionList, [12] = (void *)&C_OpenSession, [15] = (void *)&C_GetSessionInfo,
#define Y(name, n) [n] = (void *)&name,
    STUBS
#undef Y
}};
__attribute__((visibility("default"))) CK_RV C_GetFunctionList(void **list) {
    if (!list) return 5;
    *list = &table; return 0;
}
#else
#ifndef IA32_IMAGE
#define IA32_IMAGE 0
#endif
static uint64_t sequence;
static const char *module;
static unsigned image = IA32_IMAGE;
static uint64_t birth(void) {
    char text[8192]; FILE *f = fopen("/proc/self/stat", "r");
    if (!f || !fgets(text, sizeof text, f)) _exit(98);
    fclose(f); char *last = strrchr(text, ')'), *save;
    if (!last) _exit(98);
    char *token = strtok_r(last + 2, " ", &save);
    for (int i = 0; i < 19 && token; ++i) token = strtok_r(NULL, " ", &save);
    if (!token) _exit(98);
    return strtoull(token, NULL, 10);
}
static void observed_image(void) {
    struct stat exe, pidns, timens; char path[4096];
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
    if (fd < 0 || n <= 0 || n == (ssize_t)sizeof path - 1 || fstat(fd, &exe) ||
        stat("/proc/self/ns/pid", &pidns) || stat("/proc/self/ns/time", &timens)) _exit(98);
    close(fd); path[n] = 0;
    header(&sequence, image, "image"); printf(",\"ppid\":%d,\"start_time\":%" PRIu64 ",\"path\":", getppid(), birth());
    quoted(path);
    printf(",\"dev\":%" PRIu64 ",\"ino\":%" PRIu64 ",\"mtime_ns\":%" PRIu64
           ",\"pid_namespace\":%" PRIu64 ",\"time_namespace\":%" PRIu64
           ",\"pointer_bytes\":4,\"ck_ulong_bytes\":4,\"t\":%" PRIu64,
           (uint64_t)exe.st_dev, (uint64_t)exe.st_ino,
           (uint64_t)exe.st_mtim.tv_sec * UINT64_C(1000000000) + (uint64_t)exe.st_mtim.tv_nsec,
           (uint64_t)pidns.st_ino, (uint64_t)timens.st_ino, now_ns()); end_row();
}
static void target(const char *fn, void *address) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) _exit(98);
    char line[4096], perms[5]; uint64_t lo, hi, off, ino;
    unsigned major, minor; uint64_t ptr = (uintptr_t)address;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %" SCNx64 " %x:%x %" SCNu64,
                   &lo, &hi, perms, &off, &major, &minor, &ino) == 7 && ptr >= lo && ptr < hi && perms[2] == 'x' && ino) {
            header(&sequence, image, "target"); printf(",\"fn\":"); quoted(fn);
            printf(",\"dev\":[%u,%u],\"ino\":%" PRIu64 ",\"file_offset\":%" PRIu64
                   ",\"vaddr\":%" PRIu64 ",\"map_start\":%" PRIu64 ",\"map_end\":%" PRIu64
                   ",\"map_offset\":%" PRIu64 ",\"permissions\":\"%s\",\"t\":%" PRIu64,
                   major, minor, ino, ptr - lo + off, ptr, lo, hi, off, perms, now_ns());
            end_row(); fclose(f); return;
        }
    }
    _exit(98);
}
static void call(const char *fn, CK_RV rv, const char *phase, CK_SESSION_HANDLE sess, uint64_t t0) {
    uint64_t t1 = now_ns();
    header(&sequence, image, "call"); printf(",\"fn\":"); quoted(fn);
    printf(",\"rv\":%lu,\"scope\":\"selected\",\"phase\":", rv); quoted(phase);
    printf(",\"sess\":%lu,\"t0\":%" PRIu64 ",\"t1\":%" PRIu64, sess, t0, t1); end_row();
}
typedef CK_RV (*open_fn)(CK_ULONG, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
static CK_SESSION_HANDLE open_session(open_fn endpoint) {
    CK_SESSION_HANDLE session = 0;
    uint64_t t0 = now_ns(); CK_RV rv = endpoint(1, 6, NULL, NULL, &session);
    call("C_OpenSession", rv, "setup", session, t0);
    if (rv || !session) _exit(99);
    return session;
}
static uint64_t number(const char *s) {
    if (!*s) _exit(99);
    for (const char *p = s; *p; ++p) if (*p < '0' || *p > '9') _exit(99);
    char *end; errno = 0; uint64_t n = strtoull(s, &end, 10);
    if (errno || *end) _exit(99);
    return n;
}
int main(int argc, char **argv) {
    if (argc != 13 || number(argv[5]) != image ||
        (strcmp(argv[4], "leader") && strcmp(argv[4], "failed"))) return 2;
    module = argv[1]; sequence = number(argv[6]);
    uint64_t leg = number(argv[7]), setup = number(argv[8]);
    uint64_t recovery_ms = number(argv[9]), measured_ms = number(argv[10]), terminal_ms = number(argv[11]);
    uint64_t delay = number(argv[12]);
    if (now_ns() >= leg || setup > leg || !recovery_ms || recovery_ms > 15000 ||
        !measured_ms || measured_ms > 60000 || !terminal_ms || terminal_ms > 65000 || delay > 1000) return 2;
    observed_image();
    void *provider = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!provider) return 3;
    CK_RV (*initialize)(void *) = dlsym(provider, "C_Initialize");
    CK_RV (*info)(void *) = dlsym(provider, "C_GetInfo");
    open_fn session_open = dlsym(provider, "C_OpenSession");
    CK_RV (*session_info)(CK_SESSION_HANDLE, CK_SESSION_INFO *) = dlsym(provider, "C_GetSessionInfo");
    if (!initialize || !info || !session_info || !session_open) return 3;
    target("C_Initialize", (void *)initialize); target("C_GetInfo", (void *)info);
    target("C_GetSessionInfo", (void *)session_info);
    target("C_OpenSession", (void *)session_open);
    CK_SESSION_HANDLE session = image ? open_session(session_open) : 0;
    header(&sequence, image, "ready"); printf(",\"t\":%" PRIu64, now_ns()); end_row();
    ack(&sequence, image, "ready");
    uint64_t measured_deadline;
    if (!image) {
        require('G', setup);
        session = open_session(session_open);
        for (unsigned i = 0; i < 11; ++i) {
            struct request r = {.rv = i % 2 ? 5 : 0};
            uint64_t t0 = now_ns(); CK_RV rv = initialize(&r);
            call("C_Initialize", rv, "pre", 0, t0);
        }
        ack(&sequence, image, "pre");
        char next_seq[32]; char *next_argv[] = {
            argv[2], argv[1], argv[2], argv[3], argv[4], "1", next_seq,
            argv[7], argv[8], argv[9], argv[10], argv[11], argv[12], NULL};
        struct request r = {.rv = 5, .held = 1, .failed = !strcmp(argv[4], "failed"),
            .image = image, .sequence = &sequence, .t0 = now_ns(), .leg = leg,
            .deadline = phase_end(leg, recovery_ms), .measurement_ms = measured_ms,
            .exec_path = !strcmp(argv[4], "failed") ? argv[3] : argv[2],
            .exec_argv = next_argv, .next_sequence = next_seq, .birth = birth()};
        CK_RV rv = initialize(&r);
        call("C_Initialize", rv, "held-return", 0, r.t0);
        ack(&sequence, image, "held-return");
        measured_deadline = r.post_deadline;
    } else {
        uint64_t deadline = phase_end(leg, recovery_ms);
        unsigned attempts = 0;
        for (;;) {
            char byte = command(deadline);
            if (byte == 'R') break;
            if (byte != 'W' || ++attempts > 20) return 4;
            char phase[48]; snprintf(phase, sizeof phase, "successor-1-%u", attempts);
            CK_ULONG unused[32]; uint64_t t0 = now_ns(); CK_RV rv = info(unused);
            call("C_GetInfo", rv, phase, 0, t0); ack(&sequence, image, phase);
        }
        measured_deadline = phase_end(leg, measured_ms);
    }
    for (unsigned i = 0; i < 17; ++i) {
        if (now_ns() >= measured_deadline) return 5;
        if (i && delay) {
            struct timespec wait = {(time_t)(delay / 1000), (long)(delay % 1000) * 1000000};
            while (nanosleep(&wait, &wait) && errno == EINTR) {}
        }
        CK_SESSION_INFO si; uint64_t t0 = now_ns(); CK_RV rv = session_info(session, &si);
        call("C_GetSessionInfo", rv, "post", session, t0);
    }
    ack(&sequence, image, "post");
    require('F', phase_end(leg, terminal_ms)); ack(&sequence, image, "done");
    if (dlclose(provider)) return 6;
    return 0;
}
#endif
