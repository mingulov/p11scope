/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native Linux x86-64 LP64 caller. Real SoftHSM calls; no simulated provider.
 * Every provider call, including setup/teardown, has an independent ledger.
 * Interactive: calls FUNCTION COUNT DELAY_MS PHASE SCOPE | exec PATH | stop
 * Auto: MODULE IMAGE SCOPE --auto-gate PATH [--canary PRIVATE_VALUE]. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
typedef struct { CK_SLOT_ID slot; CK_ULONG state, flags, error; } CK_SESSION_INFO;
static void **fns;
static unsigned long image;
static const char *scope, *module;
static CK_SESSION_HANDLE session;
static volatile unsigned char private_buffer[64] = "N3_PRIVATE_BUFFER_91b947";
#define F(i, type) ((type)fns[i])

static unsigned long long now_ns(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) { perror("clock"); exit(1); }
  return (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
}
static void delay_ms(unsigned long ms) {
  struct timespec t = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000};
  while (nanosleep(&t, &t) && errno == EINTR) { }
}
static void quoted(const char *s) {
  putchar('"');
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
    else if (*p < 32) printf("\\u%04x", *p);
    else putchar(*p);
  }
  putchar('"');
}
static void header(const char *kind) {
  printf("N3LEDGER {\"kind\":\"%s\",\"image\":%lu", kind, image);
}
static void ack(const char *phase) {
  header("ack"); printf(",\"phase\":"); quoted(phase);
  printf(",\"t\":%llu}\n", now_ns()); fflush(stdout);
}
static void call(const char *fn, CK_RV rv, const char *phase, unsigned long long start) {
  unsigned long long finish = now_ns();
  header("call"); printf(",\"pid\":%d,\"tid\":%ld,\"fn\":", getpid(), syscall(SYS_gettid));
  quoted(fn); printf(",\"rv\":%lu,\"phase\":", rv); quoted(phase);
  printf(",\"scope\":"); quoted(scope);
  printf(",\"t0\":%llu,\"t1\":%llu}\n", start, finish); fflush(stdout);
  if (rv) { fprintf(stderr, "provider call failed: %s rv=%lu\n", fn, rv); exit(1); }
}
static int target(const char *fn, void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) return 1;
  char line[4096], perms[5]; unsigned long lo, hi, off, ino;
  unsigned int major, minor; uintptr_t ptr = (uintptr_t)address;
  while (fgets(line, sizeof line, maps)) {
    if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &lo, &hi, perms, &off, &major, &minor, &ino) == 7 &&
        ptr >= lo && ptr < hi && perms[2] == 'x' && ino) {
      header("target"); printf(",\"fn\":"); quoted(fn);
      printf(",\"dev\":[%u,%u],\"ino\":%lu,\"file_offset\":%lu}\n",
             major, minor, ino, (unsigned long)(ptr - lo) + off);
      fclose(maps); fflush(stdout); return 0;
    }
  }
  fclose(maps); return 1;
}
static unsigned long long birth(void) {
  char buf[8192]; FILE *f = fopen("/proc/self/stat", "r");
  if (!f || !fgets(buf, sizeof buf, f)) exit(1);
  fclose(f); char *p = strrchr(buf, ')');
  if (!p) exit(1);
  char *save = NULL, *token = strtok_r(p + 2, " ", &save);
  for (int i = 0; i < 19 && token; i++) token = strtok_r(NULL, " ", &save);
  if (!token) exit(1);
  return strtoull(token, NULL, 10);
}
static void observed_image(void) {
  char path[4096]; struct stat exe, pidns, timens;
  ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
  int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (n <= 0 || n == (ssize_t)sizeof path - 1 || fd < 0 || fstat(fd, &exe) ||
      stat("/proc/self/ns/pid", &pidns) || stat("/proc/self/ns/time", &timens)) exit(1);
  close(fd); path[n] = 0;
  header("image"); printf(",\"pid\":%d,\"ppid\":%d,\"start_time\":%llu,\"path\":",
                          getpid(), getppid(), birth()); quoted(path);
  printf(",\"dev\":%llu,\"ino\":%llu,\"mtime_ns\":%llu,\"pid_namespace\":%llu,"
         "\"time_namespace\":%llu,\"t\":%llu}\n",
         (unsigned long long)exe.st_dev, (unsigned long long)exe.st_ino,
         (unsigned long long)exe.st_mtim.tv_sec * 1000000000ULL + (unsigned long long)exe.st_mtim.tv_nsec,
         (unsigned long long)pidns.st_ino, (unsigned long long)timens.st_ino, now_ns()); fflush(stdout);
}
static void setup(void) {
  void *handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
  if (!handle) { fprintf(stderr, "provider load failed\n"); exit(1); }
  void *symbol = dlsym(handle, "C_GetFunctionList"), *list = NULL;
  if (!symbol || target("C_GetFunctionList", symbol)) exit(1);
  unsigned long long t = now_ns();
  CK_RV rv = ((CK_RV (*)(void **))symbol)(&list);
  call("C_GetFunctionList", rv, "setup", t);
  if (!list) exit(1);
  fns = (void **)((char *)list + 8); /* CK_VERSION plus LP64 alignment. */
  const char *names[] = {"C_Initialize", "C_Finalize", "C_GetInfo", "C_GetSlotList", "C_OpenSession",
                        "C_CloseSession", "C_GetSessionInfo", "C_GenerateRandom"};
  const int indexes[] = {0, 1, 2, 4, 12, 13, 15, 64};
  for (unsigned int i = 0; i < sizeof indexes / sizeof indexes[0]; i++)
    if (!fns[indexes[i]] || target(names[i], fns[indexes[i]])) exit(1);
  t = now_ns(); rv = F(0, CK_RV (*)(void *))(NULL); call("C_Initialize", rv, "setup", t);
  CK_SLOT_ID slots[16]; CK_ULONG n = 16;
  t = now_ns(); rv = F(4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &n);
  call("C_GetSlotList", rv, "setup", t); if (!n || n > 16) exit(1);
  t = now_ns(); rv = F(12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))
    (slots[0], 6, NULL, NULL, &session); call("C_OpenSession", rv, "setup", t);
  header("ready"); printf(",\"t\":%llu}\n", now_ns()); fflush(stdout);
}
static void teardown(void) {
  unsigned long long t = now_ns(); CK_RV rv = F(13, CK_RV (*)(CK_SESSION_HANDLE))(session);
  call("C_CloseSession", rv, "teardown", t);
  t = now_ns(); rv = F(1, CK_RV (*)(void *))(NULL); call("C_Finalize", rv, "teardown", t);
}
static void calls(const char *fn, unsigned long n, unsigned long ms, const char *phase) {
  if (n > 10000 || ms > 10000 || (strcmp(fn, "C_GenerateRandom") && strcmp(fn, "C_GetSessionInfo") && strcmp(fn, "C_GetInfo"))) exit(2);
  for (unsigned long i = 0; i < n; i++) {
    CK_RV rv; unsigned long long t = now_ns();
    if (!strcmp(fn, "C_GenerateRandom")) {
      unsigned char bytes[64];
      memcpy(bytes, (const void *)private_buffer, sizeof bytes);
      rv = F(64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(session, bytes, sizeof bytes);
    } else if (!strcmp(fn, "C_GetSessionInfo")) {
      CK_SESSION_INFO info; rv = F(15, CK_RV (*)(CK_SESSION_HANDLE, CK_SESSION_INFO *))(session, &info);
    } else {
      CK_ULONG info[32]; rv = F(2, CK_RV (*)(void *))(info);
    }
    call(fn, rv, phase, t);
    if (ms) delay_ms(ms);
  }
  ack(phase);
}
int main(int argc, char **argv) {
  if (sizeof(void *) != 8 || sizeof(unsigned long) != 8 || argc < 4) return 2;
  module = argv[1]; image = strtoul(argv[2], NULL, 10); scope = argv[3];
  const char *gate = NULL;
  for (int i = 4; i < argc; i += 2) {
    if (i + 1 >= argc) return 2;
    if (!strcmp(argv[i], "--auto-gate")) gate = argv[i + 1];
    else if (!strcmp(argv[i], "--canary")) { private_buffer[63] ^= (unsigned char)argv[i + 1][0]; }
    else return 2;
  }
  const char *env = getenv("N3_PRIVATE_ENV");
  if (env) private_buffer[62] ^= (unsigned char)env[0];
  observed_image(); setup();
  if (gate) {
    unsigned long long end = now_ns() + 30000000000ULL;
    while (access(gate, F_OK)) { if (now_ns() >= end) return 1; delay_ms(10); }
    calls("C_GenerateRandom", 20, 200, "main"); teardown(); ack("done"); return 0;
  }
  char line[8192], fn[64], phase[64], next_scope[64], path[4096];
  unsigned long n, ms;
  while (fgets(line, sizeof line, stdin)) {
    if (!strcmp(line, "stop\n")) { teardown(); ack("done"); return 0; }
    if (sscanf(line, "calls %63s %lu %lu %63s %63s", fn, &n, &ms, phase, next_scope) == 5) {
      scope = next_scope; calls(fn, n, ms, phase); continue;
    }
    if (sscanf(line, "exec %4095s", path) == 1) {
      char next_image[32]; snprintf(next_image, sizeof next_image, "%lu", image + 1);
      execl(path, path, module, next_image, "outside", (char *)NULL); perror("exec"); return 1;
    }
    return 2;
  }
  teardown(); ack("done"); return 0;
}
