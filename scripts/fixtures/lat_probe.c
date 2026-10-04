/* SPDX-License-Identifier: GPL-3.0-or-later */
/* lat_probe: per-call latency of a SoftHSM2 client (Task 6 C5 measurement M6, DR-39).
 *
 * usage: lat_probe MODULE SECONDS MMAP_EVERY OUT
 *
 * Initializes MODULE (C_Initialize, C_GetSlotList, C_OpenSession), then for
 * SECONDS calls C_GenerateRandom(16 bytes) back to back on one thread and
 * times every call with CLOCK_MONOTONIC. MMAP_EVERY > 0 also maps, touches
 * and unmaps one 64 KiB anonymous region every MMAP_EVERY calls and times
 * that separately: mmap/munmap take the target's mmap_lock for writing, the
 * lock a /proc/PID/maps reader (the observer's scan) holds for reading, so
 * this is where a scan-induced target stall shows (DR-39).
 *
 * OUT gets one SUMMARY line per series:
 *   SUMMARY series=call|mmap n=N p50_ns=.. p90_ns=.. p99_ns=.. p999_ns=.. max_ns=..
 *           over_1ms=N over_10ms=N over_100ms=N seconds=S
 * Latencies are kept in a log-linear histogram (100 ns steps below 100 us,
 * 10 us steps below 100 ms, 1 ms steps above, capped at 10 s); percentiles
 * are the upper bound of their bucket, max is exact. A failed call counts
 * as a failure (fails=N on the call series); any failure makes the exit 1.
 * Exit: 0 ok, 1 provider or I/O failure, 2 usage. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
static void **fns;
#define F(i, t) ((t)fns[i])

#define FINE 1000      /* 100 ns steps up to 100 us */
#define MID 9990       /* 10 us steps up to 100 ms */
#define COARSE 9900    /* 1 ms steps up to 10 s */
#define BUCKETS (FINE + MID + COARSE + 1)

struct series {
  unsigned long long n, max, over1, over10, over100, fails;
  unsigned long long *hist;
};

static unsigned long long now_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (unsigned long long)t.tv_sec * 1000000000ull + (unsigned long long)t.tv_nsec;
}

static size_t bucket(unsigned long long ns) {
  if (ns < 100000ull) return (size_t)(ns / 100);
  if (ns < 100000000ull) return FINE + (size_t)((ns - 100000ull) / 10000);
  unsigned long long ms = (ns - 100000000ull) / 1000000ull;
  return FINE + MID + (size_t)(ms < COARSE ? ms : COARSE);
}

static unsigned long long upper(size_t b) {
  if (b < FINE) return (unsigned long long)(b + 1) * 100;
  if (b < FINE + MID) return 100000ull + (unsigned long long)(b - FINE + 1) * 10000;
  return 100000000ull + (unsigned long long)(b - FINE - MID + 1) * 1000000ull;
}

static void note(struct series *s, unsigned long long ns) {
  s->n++;
  s->hist[bucket(ns)]++;
  if (ns > s->max) s->max = ns;
  if (ns > 1000000ull) s->over1++;
  if (ns > 10000000ull) s->over10++;
  if (ns > 100000000ull) s->over100++;
}

static unsigned long long quantile(const struct series *s, double q) {
  if (!s->n) return 0;
  unsigned long long want = (unsigned long long)(q * (double)s->n);
  if (want >= s->n) want = s->n - 1;
  unsigned long long seen = 0;
  for (size_t b = 0; b < BUCKETS; b++) {
    seen += s->hist[b];
    if (seen > want) return upper(b) < s->max ? upper(b) : s->max;
  }
  return s->max;
}

static void report(FILE *out, const char *name, const struct series *s, double secs) {
  fprintf(out,
          "SUMMARY series=%s n=%llu p50_ns=%llu p90_ns=%llu p99_ns=%llu p999_ns=%llu max_ns=%llu "
          "over_1ms=%llu over_10ms=%llu over_100ms=%llu fails=%llu seconds=%.3f\n",
          name, s->n, quantile(s, 0.5), quantile(s, 0.9), quantile(s, 0.99), quantile(s, 0.999),
          s->max, s->over1, s->over10, s->over100, s->fails, secs);
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "usage: lat_probe MODULE SECONDS MMAP_EVERY OUT\n");
    return 2;
  }
  double secs = atof(argv[2]);
  long every = atol(argv[3]);
  if (secs <= 0 || every < 0) {
    fprintf(stderr, "lat_probe: SECONDS > 0 and MMAP_EVERY >= 0\n");
    return 2;
  }
  struct series call = {0}, map = {0};
  call.hist = calloc(BUCKETS, sizeof *call.hist);
  map.hist = calloc(BUCKETS, sizeof *map.hist);
  if (!call.hist || !map.hist) return 1;
  void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) { fprintf(stderr, "lat_probe: dlopen: %s\n", dlerror()); return 1; }
  unsigned long (*gfl)(void **) = (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
  void *list = 0;
  if (!gfl || gfl(&list) || !list) return 1;
  fns = (void **)((char *)list + 8);
  if (F(0, CK_RV (*)(void *))(NULL)) { fprintf(stderr, "lat_probe: C_Initialize\n"); return 1; }
  CK_SLOT_ID slots[16]; CK_ULONG ns = 16;
  if (F(4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &ns) || !ns) return 1;
  CK_SESSION_HANDLE s;
  if (F(12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(slots[0], 6, 0, 0, &s))
    return 1;
  unsigned char buf[16];
  unsigned long long start = now_ns(), end = start + (unsigned long long)(secs * 1e9), t = start;
  long since = 0;
  while (t < end) {
    unsigned long long a = now_ns();
    CK_RV rv = F(64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(s, buf, sizeof buf);
    t = now_ns();
    note(&call, t - a);
    if (rv) call.fails++;
    if (every && ++since >= every) {
      since = 0;
      a = now_ns();
      char *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (p == MAP_FAILED) { map.fails++; continue; }
      memset(p, 1, 65536);
      munmap(p, 65536);
      t = now_ns();
      note(&map, t - a);
    }
  }
  double took = (double)(t - start) / 1e9;
  F(13, CK_RV (*)(CK_SESSION_HANDLE))(s);
  F(1, CK_RV (*)(void *))(NULL);
  FILE *out = fopen(argv[4], "w");
  if (!out) { perror("lat_probe: OUT"); return 1; }
  report(out, "call", &call, took);
  if (every) report(out, "mmap", &map, took);
  if (fclose(out)) return 1;
  return call.fails || map.fails ? 1 : 0;
}
