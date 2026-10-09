/* SPDX-License-Identifier: GPL-3.0-or-later */
/* gated: ledgered SoftHSM2 client. usage: gated MODULE ITERS SLEEP_US GATEFILE
 * Sets up (Initialize/GetSlotList/OpenSession/Login), prints READY, waits for GATEFILE to exist,
 * runs ITERS x {GenerateRandom, DigestInit, Digest, FindObjectsInit, FindObjects, FindObjectsFinal},
 * prints LEDGER, then waits for SIGTERM/SIGINT before Logout/CloseSession/Finalize.
 * GATEFILE "-" = no gate, no wait at end (exits right after the loop). */
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
/* Independent physical target evidence, read from this client's actual VMA.
 * The hash is supplied by the runner's before/after file pin, never the report. */
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
int main(int argc, char **argv) {
  if (argc != 5) { fprintf(stderr, "usage: gated MODULE ITERS SLEEP_US GATEFILE\n"); return 2; }
  long n = atol(argv[2]), us = atol(argv[3]); const char *gate = argv[4]; int gated = strcmp(gate, "-") != 0;
  signal(SIGTERM, on); signal(SIGINT, on);
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
  for (int i = 0; i < 6; i++) if (target(names[i], fns[ordinals[i]])) return 1;
  printf("READY pid=%d\n", getpid()); fflush(stdout);
  if (gated) while (access(gate, F_OK) != 0 && !stop) usleep(10000);
  unsigned char buf[64], out[32]; CK_ULONG ol, cnt; CK_MECHANISM m = {0x250, 0, 0}; CK_OBJECT_HANDLE oh[4];
  unsigned long successful[6] = {0}, done = 0;
  for (long i = 0; i < n && !stop; i++, done++) {
    successful[0] += F(64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(s, buf, sizeof buf) == 0;
    successful[1] += F(37, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *))(s, &m) == 0;
    ol = sizeof out;
    successful[2] += F(38, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *))(s, buf, sizeof buf, out, &ol) == 0;
    successful[3] += F(26, CK_RV (*)(CK_SESSION_HANDLE, void *, CK_ULONG))(s, 0, 0) == 0;
    successful[4] += F(27, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *))(s, oh, 4, &cnt) == 0;
    successful[5] += F(28, CK_RV (*)(CK_SESSION_HANDLE))(s) == 0;
    if (us > 0) usleep(us);
  }
  unsigned long bad = 0;
  printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":%d,\"complete\":%s,\"functions\":[",
         getpid(), done == (unsigned long)n ? "true" : "false");
  for (int i = 0; i < 6; i++) {
    bad += done - successful[i];
    printf("%s{\"name\":\"%s\",\"attempts\":%lu,\"successful\":%lu}",
           i ? "," : "", names[i], done, successful[i]);
  }
  printf("]}\n"); fflush(stdout);
  if (gated) while (!stop) pause();
  F(19, CK_RV (*)(CK_SESSION_HANDLE))(s); F(13, CK_RV (*)(CK_SESSION_HANDLE))(s); F(1, CK_RV (*)(void *))(NULL);
  return bad ? 1 : 0;
}
