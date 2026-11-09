/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* short-lived-caller: minimal-lifetime SoftHSM2 client for --track-short-lived.
 * usage: short-lived-caller MODULE N GATEFILE
 * Sets up, prints READY, waits for GATEFILE, runs N x {GenerateRandom} with
 * no pacing, prints LEDGER, tears down and exits immediately (no signal wait).
 * The post-gate lifetime is a few milliseconds. All instances may share one
 * gate file: the harness moves every READY process into the target cgroup,
 * then releases the gate once. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
static void **fns; static volatile sig_atomic_t stop;
static void on(int s) { (void)s; stop = 1; }
#define F(i, t) ((t)fns[i])
int main(int argc, char **argv) {
  if (argc != 4) { fprintf(stderr, "usage: short-lived-caller MODULE N GATEFILE\n"); return 2; }
  long n = atol(argv[2]); const char *gate = argv[3]; int gated = strcmp(gate, "-") != 0;
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
  printf("READY pid=%d\n", getpid()); fflush(stdout);
  if (gated) while (access(gate, F_OK) != 0 && !stop) usleep(1000);
  if (stop) return 1;
  unsigned char buf[32];
  unsigned long successful = 0, done = 0;
  for (long i = 0; i < n && !stop; i++, done++) {
    successful += F(64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(s, buf, sizeof buf) == 0;
  }
  printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":%d,\"complete\":%s,\"functions\":[",
         getpid(), done == (unsigned long)n ? "true" : "false");
  printf("{\"name\":\"C_GenerateRandom\",\"attempts\":%lu,\"successful\":%lu}", done, successful);
  /* Teardown runs after LEDGER but before exit, while the observer still
   * records; the pre-gate setup is not observed. */
  printf(",{\"name\":\"C_Logout\",\"attempts\":1,\"successful\":1}");
  printf(",{\"name\":\"C_CloseSession\",\"attempts\":1,\"successful\":1}");
  printf(",{\"name\":\"C_Finalize\",\"attempts\":1,\"successful\":1}]}\n");
  fflush(stdout);
  F(19, CK_RV (*)(CK_SESSION_HANDLE))(s); F(13, CK_RV (*)(CK_SESSION_HANDLE))(s); F(1, CK_RV (*)(void *))(NULL);
  return (done - successful) ? 1 : 0;
}
