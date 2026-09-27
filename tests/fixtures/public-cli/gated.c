/* SPDX-License-Identifier: GPL-3.0-or-later */
/* gated: ledgered SoftHSM2 client. usage: gated MODULE ITERS SLEEP_US GATEFILE
 * Sets up (Initialize/GetSlotList/OpenSession/Login), prints READY, waits for GATEFILE to exist,
 * runs ITERS x {GenerateRandom, DigestInit, Digest, FindObjectsInit, FindObjects, FindObjectsFinal},
 * prints LEDGER, then waits for SIGTERM/SIGINT before Logout/CloseSession/Finalize.
 * GATEFILE "-" = no gate, no wait at end (exits right after the loop). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE;
typedef struct { unsigned long mechanism; void *p; unsigned long len; } CK_MECHANISM;
static void **fns; static volatile sig_atomic_t stop;
static void on(int s) { (void)s; stop = 1; }
#define F(i, t) ((t)fns[i])
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
  F(18, CK_RV (*)(CK_SESSION_HANDLE, unsigned long, unsigned char *, CK_ULONG))(s, 1, (unsigned char *)"1234", 4);
  printf("READY pid=%d\n", getpid()); fflush(stdout);
  if (gated) while (access(gate, F_OK) != 0 && !stop) usleep(10000);
  unsigned char buf[64], out[32]; CK_ULONG ol, cnt; CK_MECHANISM m = {0x250, 0, 0}; CK_OBJECT_HANDLE oh[4];
  unsigned long bad = 0, done = 0;
  for (long i = 0; i < n && !stop; i++, done++) {
    bad += F(64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(s, buf, sizeof buf) != 0;
    bad += F(37, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *))(s, &m) != 0;
    ol = sizeof out;
    bad += F(38, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *))(s, buf, sizeof buf, out, &ol) != 0;
    bad += F(26, CK_RV (*)(CK_SESSION_HANDLE, void *, CK_ULONG))(s, 0, 0) != 0;
    bad += F(27, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *))(s, oh, 4, &cnt) != 0;
    bad += F(28, CK_RV (*)(CK_SESSION_HANDLE))(s) != 0;
    if (us > 0) usleep(us);
  }
  printf("LEDGER iterations=%lu nonzero_rv=%lu\n", done, bad); fflush(stdout);
  if (gated) while (!stop) pause();
  F(19, CK_RV (*)(CK_SESSION_HANDLE))(s); F(13, CK_RV (*)(CK_SESSION_HANDLE))(s); F(1, CK_RV (*)(void *))(NULL);
  return 0;
}
