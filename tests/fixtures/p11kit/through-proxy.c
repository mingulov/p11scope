/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* through-proxy: ledgered PKCS#11 client for the p11-kit transparency cells.
 * usage: through-proxy MODULE ITERS SLEEP_US SETTLE_MS GATEFILE
 * Prints READY before the first PKCS#11 call (and before dlopen), waits for
 * GATEFILE to exist, then performs exactly one C_GetFunctionList plus one setup
 * (Initialize, GetSlotList, OpenSession, Login), sleeps SETTLE_MS to let a
 * late-load observer discover the freshly mapped modules and attach, then runs
 * ITERS x {DigestInit, Digest, FindObjectsInit, FindObjects, FindObjectsFinal}
 * and exactly one teardown (CloseSession, Finalize). Prints LEDGER after every
 * call completed, then waits for SIGTERM/SIGINT before exiting.
 * GATEFILE "-" = no gate, no wait at end (exits right after the ledger).
 * Logout is deliberately omitted: close-then-finalize exercises C_CloseSession
 * while keeping the ledger to the cell's fixed set.
 * Timing contract: the setup calls race loader attach by construction (the
 * backends load inside C_Initialize, microseconds before their first calls),
 * so the cells check setup as exact-or-covered; the loop and teardown run
 * after the settle and must be exact. A too-short settle fails loudly as a
 * loop deficit, never silently. */
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
/* Independent physical target evidence, read from this client's actual VMA. */
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
static const char *loop_names[] = {"C_DigestInit", "C_Digest",
  "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"};
static const int loop_ordinals[] = {37, 38, 26, 27, 28};
static const char *setup_names[] = {"C_Initialize", "C_GetSlotList",
  "C_OpenSession", "C_Login", "C_CloseSession", "C_Finalize"};
static const int setup_ordinals[] = {0, 4, 12, 18, 13, 1};
int main(int argc, char **argv) {
  if (argc != 6) { fprintf(stderr, "usage: through-proxy MODULE ITERS SLEEP_US SETTLE_MS GATEFILE\n"); return 2; }
  long n = atol(argv[2]), us = atol(argv[3]), settle = atol(argv[4]); const char *gate = argv[5]; int gated = strcmp(gate, "-") != 0;
  if (n <= 0 || settle < 0) { fprintf(stderr, "ITERS must be positive, SETTLE_MS nonnegative\n"); return 2; }
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
  unsigned long ok_init, ok_slots, ok_open, ok_login;
  ok_init = F(0, CK_RV (*)(void *))(NULL) == 0;
  CK_SLOT_ID slots[16]; CK_ULONG ns = 16;
  ok_slots = ok_init && (F(4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &ns) == 0) && ns;
  CK_SESSION_HANDLE s = 0;
  ok_open = ok_slots && (F(12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(slots[0], 6, 0, 0, &s) == 0);
  ok_login = ok_open && (F(18, CK_RV (*)(CK_SESSION_HANDLE, unsigned long, unsigned char *, CK_ULONG))(s, 1, (unsigned char *)"1234", 4) == 0);
  if (!ok_login) return 1;
  /* Pin every called address: the proxy's live entry points stay ["unknown"]
   * (heuristic tables are never ordinal-named), so the oracle attributes the
   * proxy layer by physical target, never by name. */
  if (target("C_GetFunctionList", (void *)gfl)) return 1;
  for (int i = 0; i < 6; i++) if (target(setup_names[i], fns[setup_ordinals[i]])) return 1;
  for (int i = 0; i < 5; i++) if (target(loop_names[i], fns[loop_ordinals[i]])) return 1;
  for (long waited = 0; waited < settle && !stop; waited += 100) usleep(100000);
  unsigned char buf[64], out[32]; CK_ULONG ol, cnt; CK_MECHANISM m = {0x250, 0, 0}; CK_OBJECT_HANDLE oh[4];
  unsigned long successful[5] = {0}, done = 0;
  for (long i = 0; i < n && !stop; i++, done++) {
    successful[0] += F(37, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *))(s, &m) == 0;
    ol = sizeof out;
    successful[1] += F(38, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *))(s, buf, sizeof buf, out, &ol) == 0;
    successful[2] += F(26, CK_RV (*)(CK_SESSION_HANDLE, void *, CK_ULONG))(s, 0, 0) == 0;
    successful[3] += F(27, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *))(s, oh, 4, &cnt) == 0;
    successful[4] += F(28, CK_RV (*)(CK_SESSION_HANDLE))(s) == 0;
    if (us > 0) usleep(us);
  }
  unsigned long ok_close = F(13, CK_RV (*)(CK_SESSION_HANDLE))(s) == 0;
  unsigned long ok_final = F(1, CK_RV (*)(void *))(NULL) == 0;
  unsigned long bad = (done != (unsigned long)n) + !ok_init + !ok_slots + !ok_open + !ok_login + !ok_close + !ok_final;
  printf("LEDGER {\"schema\":\"p11scope/p11kit-ledger/v1\",\"pid\":%d,\"complete\":%s,\"functions\":[",
         getpid(), done == (unsigned long)n ? "true" : "false");
  printf("{\"name\":\"C_GetFunctionList\",\"attempts\":1,\"successful\":1},");
  printf("{\"name\":\"C_Initialize\",\"attempts\":1,\"successful\":%lu},", ok_init);
  printf("{\"name\":\"C_GetSlotList\",\"attempts\":1,\"successful\":%lu},", ok_slots);
  printf("{\"name\":\"C_OpenSession\",\"attempts\":1,\"successful\":%lu},", ok_open);
  printf("{\"name\":\"C_Login\",\"attempts\":1,\"successful\":%lu},", ok_login);
  for (int i = 0; i < 5; i++) {
    bad += done - successful[i];
    printf("{\"name\":\"%s\",\"attempts\":%lu,\"successful\":%lu},", loop_names[i], done, successful[i]);
  }
  printf("{\"name\":\"C_CloseSession\",\"attempts\":1,\"successful\":%lu},", ok_close);
  printf("{\"name\":\"C_Finalize\",\"attempts\":1,\"successful\":%lu}", ok_final);
  printf("]}\n"); fflush(stdout);
  if (gated) while (!stop) pause();
  return bad ? 1 : 0;
}
