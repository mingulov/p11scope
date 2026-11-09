/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* reload-workload: ledgered SoftHSM2 client with a mid-capture provider reload.
 * usage: reload-workload MODULE N1 N2 GATEFILE
 * Sets up, prints READY, waits for GATEFILE, runs N1 x {6 functions},
 * tears down (Logout/CloseSession/Finalize), dlcloses the provider, sleeps
 * 1 s unloaded, dlopens it again, sets up again, runs N2 x {6 functions},
 * prints LEDGER with the combined totals, then waits for SIGTERM/SIGINT
 * before the final teardown. GATEFILE "-" = no gate, no wait at end. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE;
typedef struct { unsigned long mechanism; void *p; unsigned long len; } CK_MECHANISM;
static void **fns; static volatile sig_atomic_t stop;
static void on(int s) { (void)s; stop = 1; }
#define F(i, t) ((t)fns[i])
static int target(const char *name, void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) return 1;
  char line[4096], perms[5]; unsigned long lo, hi, off, ino; unsigned int major, minor;
  uintptr_t ptr = (uintptr_t)address;
  while (fgets(line, sizeof line, maps)) {
    if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &lo, &hi, perms, &off, &major, &minor, &ino) == 7 &&
        ptr >= lo && ptr < hi && perms[2] == 'x' && ino) {
      printf("TARGET {\"name\":\"%s\",\"dev\":[%u,%u],\"ino\":%lu,\"file_offset\":%lu}\n",
             name, major, minor, ino, (unsigned long)(ptr - lo) + off);
      fclose(maps); return 0;
    }
  }
  fclose(maps); return 1;
}
static const char *names[] = {"C_GenerateRandom", "C_DigestInit", "C_Digest",
  "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"};
static const int ordinals[] = {64, 37, 38, 26, 27, 28};
static void *handle;
static CK_SESSION_HANDLE session;
static int setup(const char *module) {
  handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
  if (!handle) { fprintf(stderr, "dlopen %s\n", dlerror()); return 1; }
  unsigned long (*gfl)(void **) = (unsigned long (*)(void **))dlsym(handle, "C_GetFunctionList");
  void *list = 0;
  if (!gfl || gfl(&list) || !list) return 1;
  fns = (void **)((char *)list + 8);
  if (F(0, CK_RV (*)(void *))(NULL)) return 1;
  CK_SLOT_ID slots[16]; CK_ULONG ns = 16;
  if (F(4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &ns) || !ns) return 1;
  if (F(12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(slots[0], 6, 0, 0, &session)) return 1;
  if (F(18, CK_RV (*)(CK_SESSION_HANDLE, unsigned long, unsigned char *, CK_ULONG))(session, 1, (unsigned char *)"1234", 4)) return 1;
  return 0;
}
static void teardown(void) {
  F(19, CK_RV (*)(CK_SESSION_HANDLE))(session);
  F(13, CK_RV (*)(CK_SESSION_HANDLE))(session);
  F(1, CK_RV (*)(void *))(NULL);
  dlclose(handle); handle = 0;
}
static unsigned long successful[6] = {0};
static unsigned long run_loop(long n) {
  unsigned char buf[64], out[32]; CK_ULONG ol, cnt; CK_MECHANISM m = {0x250, 0, 0}; CK_OBJECT_HANDLE oh[4];
  unsigned long done = 0;
  for (long i = 0; i < n && !stop; i++, done++) {
    successful[0] += F(64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(session, buf, sizeof buf) == 0;
    successful[1] += F(37, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *))(session, &m) == 0;
    ol = sizeof out;
    successful[2] += F(38, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *))(session, buf, sizeof buf, out, &ol) == 0;
    successful[3] += F(26, CK_RV (*)(CK_SESSION_HANDLE, void *, CK_ULONG))(session, 0, 0) == 0;
    successful[4] += F(27, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *))(session, oh, 4, &cnt) == 0;
    successful[5] += F(28, CK_RV (*)(CK_SESSION_HANDLE))(session) == 0;
  }
  return done;
}
int main(int argc, char **argv) {
  if (argc != 5) { fprintf(stderr, "usage: reload-workload MODULE N1 N2 GATEFILE\n"); return 2; }
  long n1 = atol(argv[2]), n2 = atol(argv[3]); const char *gate = argv[4]; int gated = strcmp(gate, "-") != 0;
  signal(SIGTERM, on); signal(SIGINT, on);
  if (setup(argv[1])) return 1;
  for (int i = 0; i < 6; i++) if (target(names[i], fns[ordinals[i]])) return 1;
  printf("READY pid=%d\n", getpid()); fflush(stdout);
  if (gated) while (access(gate, F_OK) != 0 && !stop) usleep(10000);
  unsigned long done1 = run_loop(n1);
  teardown();
  sleep(1);
  if (stop) return 1;
  if (setup(argv[1])) return 1;
  unsigned long done2 = run_loop(n2);
  unsigned long total = done1 + done2, bad = 0;
  printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":%d,\"complete\":%s,\"functions\":[",
         getpid(), (done1 == (unsigned long)n1 && done2 == (unsigned long)n2) ? "true" : "false");
  for (int i = 0; i < 6; i++) {
    bad += total - successful[i];
    printf("%s{\"name\":\"%s\",\"attempts\":%lu,\"successful\":%lu}",
           i ? "," : "", names[i], total, successful[i]);
  }
  /* Mid-capture teardown (Logout/CloseSession/Finalize) and second setup
   * (GetFunctionList/Initialize/GetSlotList/OpenSession/Login) run
   * post-gate and are observed; the pre-gate first setup and the
   * post-observer final teardown are not. */
  static const char *extra[] = {"C_Logout", "C_CloseSession", "C_Finalize",
    "C_GetFunctionList", "C_Initialize", "C_GetSlotList", "C_OpenSession",
    "C_Login"};
  for (int i = 0; i < 8; i++) {
    printf(",{\"name\":\"%s\",\"attempts\":1,\"successful\":1}", extra[i]);
  }
  printf("]}\n"); fflush(stdout);
  if (gated) while (!stop) pause();
  F(19, CK_RV (*)(CK_SESSION_HANDLE))(session); F(13, CK_RV (*)(CK_SESSION_HANDLE))(session); F(1, CK_RV (*)(void *))(NULL);
  return bad ? 1 : 0;
}
