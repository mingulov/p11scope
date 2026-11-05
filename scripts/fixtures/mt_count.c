/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mt_count: N threads hammer C_GenerateRandom on SoftHSM2 for SECS seconds
 * behind a gate file; prints the exact total plus the measured window.
 *
 * Usage: mt_count MODULE THREADS SECS GATE PAD
 *
 * Every worker opens its session AFTER the gate opens, so every PKCS#11
 * call except C_Initialize/C_GetSlotList (pre-gate, unobserved) lands
 * after the observer attaches: the observer must count exactly
 * TOTAL + 2*THREADS + 1 (hammer calls + per-thread open/close + Finalize).
 * C_GetFunctionList arrives via dlsym on the export, which the entry
 * probes do not cover, so it is never counted. Any shortfall (a thread
 * that never ran, a failed session, a missing TOTAL) exits nonzero, so a
 * sample that did not run exactly as scripted can never count.
 *
 * The gate flags are sequentially-consistent atomics, never volatile
 * cross-thread communication (A:DR-T3A-14): every worker observes go/stop
 * exactly once published. Each worker records every C_GenerateRandom
 * attempt and every failed return separately; any failure aborts the
 * sample before MT_COUNT, so an emitted ops total always equals attempts
 * with failed=0 and the observer's entry-side count matches exactly.
 *
 * PAD=1 strides the per-thread counters at one cache line each (the
 * t12-nolock cell: no false sharing); PAD=0 packs them like mt.c.
 * Main clocks the gate-open window with CLOCK_MONOTONIC and prints one
 * MT_COUNT line: ops (exact C_GenerateRandom total), wall_ns (measured
 * window), threads, pad, attempts, failed. Per-call cost is
 * threads*wall_ns/ops.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_FLAGS;
typedef struct { void *c, *d, *l, *u; CK_FLAGS flags; void *r; } INITARGS;

static void **fns;
static CK_SLOT_ID slot;
static int go, stop;
static unsigned long packed[256];
static unsigned long packed_failed[256];
struct padline { unsigned long n; char pad[64 - sizeof(unsigned long)]; };
static struct padline padded[256];
static struct padline padded_failed[256];
static int use_pad;
static int failures;

#define GO_ON() __atomic_load_n(&go, __ATOMIC_SEQ_CST)
#define STOP_ON() __atomic_load_n(&stop, __ATOMIC_SEQ_CST)

#define F(i, t) ((t)fns[i])

static unsigned long long now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static void *worker(void *arg)
{
	long id = (long)arg;
	CK_SESSION_HANDLE s;
	unsigned char b[16];
	unsigned long local = 0, local_failed = 0;

	while (!GO_ON())
		;
	if (F(12, CK_RV(*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(slot, 4 | 2, 0, 0, &s)) {
		fprintf(stderr, "open fail\n");
		__atomic_add_fetch(&failures, 1, __ATOMIC_SEQ_CST);
		return 0;
	}
	while (!STOP_ON()) {
		local++;
		if (F(64, CK_RV(*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(s, b, sizeof b))
			local_failed++;
	}
	if (F(13, CK_RV(*)(CK_SESSION_HANDLE))(s)) {
		fprintf(stderr, "close fail\n");
		__atomic_add_fetch(&failures, 1, __ATOMIC_SEQ_CST);
		return 0;
	}
	if (use_pad) {
		padded[id].n = local;
		padded_failed[id].n = local_failed;
	} else {
		packed[id] = local;
		packed_failed[id] = local_failed;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 6) {
		fprintf(stderr, "usage: %s MODULE THREADS SECS GATE PAD\n", argv[0]);
		return 2;
	}
	int n = atoi(argv[2]);
	int secs = atoi(argv[3]);
	const char *gate = argv[4];
	use_pad = atoi(argv[5]);
	if (n < 1 || n > 256 || secs < 1 || (use_pad != 0 && use_pad != 1) || gate[0] == '\0') {
		fprintf(stderr, "bad args\n");
		return 2;
	}
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	unsigned long (*g)(void **);
	*(void **)&g = dlsym(h, "C_GetFunctionList");
	if (!g) {
		fprintf(stderr, "no C_GetFunctionList\n");
		return 1;
	}
	void *l;
	g(&l);
	fns = (void **)((char *)l + 8);
	INITARGS a;
	memset(&a, 0, sizeof a);
	a.flags = 2;
	if (F(0, CK_RV(*)(void *))(&a)) {
		fprintf(stderr, "init\n");
		return 1;
	}
	CK_SLOT_ID sl[8];
	CK_ULONG ns = 8;
	if (F(4, CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, sl, &ns) || ns < 1) {
		fprintf(stderr, "slots\n");
		return 1;
	}
	slot = sl[0];
	pthread_t t[256];
	for (long i = 0; i < n; i++) {
		if (pthread_create(&t[i], 0, worker, (void *)i)) {
			fprintf(stderr, "thread\n");
			return 1;
		}
	}
	printf("READY pid=%d\n", getpid());
	fflush(stdout);
	while (access(gate, F_OK) != 0)
		usleep(10000);
	unsigned long long t0 = now_ns();
	__atomic_store_n(&go, 1, __ATOMIC_SEQ_CST);
	sleep((unsigned int)secs);
	__atomic_store_n(&stop, 1, __ATOMIC_SEQ_CST);
	unsigned long long t1 = now_ns();
	unsigned long tot = 0, tot_failed = 0;
	for (int i = 0; i < n; i++) {
		pthread_join(t[i], 0);
		tot += use_pad ? padded[i].n : packed[i];
		tot_failed += use_pad ? padded_failed[i].n : packed_failed[i];
	}
	if (__atomic_load_n(&failures, __ATOMIC_SEQ_CST)) {
		fprintf(stderr, "worker failures\n");
		return 1;
	}
	if (tot_failed) {
		fprintf(stderr, "failed calls: %lu\n", tot_failed);
		return 1;
	}
	F(1, CK_RV(*)(void *))(0);
	if (tot == 0) {
		fprintf(stderr, "zero calls\n");
		return 1;
	}
	printf("MT_COUNT ops=%lu wall_ns=%llu threads=%d pad=%d attempts=%lu failed=%lu\n",
	       tot, t1 - t0, n, use_pad, tot, tot_failed);
	return 0;
}
