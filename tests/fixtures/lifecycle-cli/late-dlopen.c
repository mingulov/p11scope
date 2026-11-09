/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* late-dlopen: ledgered SoftHSM2 client that maps the provider only after
 * the gate opens, then calls immediately. usage: late-dlopen MODULE N GATEFILE
 * Prints READY before any dlopen, waits for GATEFILE, dlopens MODULE, sets
 * up, runs N x {GenerateRandom} with no pacing delay, prints LEDGER, then
 * waits for SIGTERM/SIGINT before teardown. With --prearm-module the first
 * calls are counted exactly; without it the documented late-load gap applies. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
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
int main(int argc, char **argv) {
  if (argc != 4) { fprintf(stderr, "usage: late-dlopen MODULE N GATEFILE\n"); return 2; }
  long n = atol(argv[2]); const char *gate = argv[3]; int gated = strcmp(gate, "-") != 0;
  signal(SIGTERM, on); signal(SIGINT, on);
  printf("READY pid=%d\n", getpid()); fflush(stdout);
  if (gated) while (access(gate, F_OK) != 0 && !stop) usleep(10000);
  if (stop) return 1;
  void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) { fprintf(stderr, "dlopen %s\n", dlerror()); return 1; }
  unsigned long (*gfl)(void **) = (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
  void *list = 0;
  if (!gfl || gfl(&list) || !list) return 1;
  fns = (void **)((char *)list + 8);
  if (F(0, CK_RV (*)(void *))(NULL)) return 1;
  CK_SLOT_ID slots[16]; CK_ULONG ns = 16;
  if (F(4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &ns) || !ns) return 1;
  CK_SESSION_HANDLE s;
  if (F(12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(slots[0], 6, 0, 0, &s)) return 1;
  if (F(18, CK_RV (*)(CK_SESSION_HANDLE, unsigned long, unsigned char *, CK_ULONG))(s, 1, (unsigned char *)"1234", 4)) return 1;
  if (target("C_GenerateRandom", fns[64])) return 1;
  unsigned char buf[64];
  unsigned long successful = 0, done = 0;
  for (long i = 0; i < n && !stop; i++, done++) {
    successful += F(64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(s, buf, sizeof buf) == 0;
  }
  printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":%d,\"complete\":%s,\"functions\":[",
         getpid(), done == (unsigned long)n ? "true" : "false");
  printf("{\"name\":\"C_GenerateRandom\",\"attempts\":%lu,\"successful\":%lu}]}\n", done, successful);
  fflush(stdout);
  if (gated) while (!stop) pause();
  F(19, CK_RV (*)(CK_SESSION_HANDLE))(s); F(13, CK_RV (*)(CK_SESSION_HANDLE))(s); F(1, CK_RV (*)(void *))(NULL);
  return (done - successful) ? 1 : 0;
}
