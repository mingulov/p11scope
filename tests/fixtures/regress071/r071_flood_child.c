/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* r071_flood_child: map the provider, C_Initialize, one C_GetSlotList,
 * mmap+touch MIB megabytes (0 skips), print READY, do K counted call
 * rounds, print COUNTS, then sleep until killed. Cells (b) and (d)
 * run N-way sync bursts and SIGKILL each burst back-to-back.
 *
 * usage: r071_flood_child PROVIDER K_ITERS MIB
 * stdout: READY pid=%d, then COUNTS init=.. slotlist=.. getinfo=..
 *   getslotinfo=.. gettokeninfo=.. failed=..
 * Table indices follow tkill_child.c (fns = table + 8).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID;
typedef struct { void *c, *d, *l, *u; unsigned long flags; void *r; } INITARGS;
#define F(i, t) ((t)fns[i])
static void **fns;

struct touch_quad { char *base; size_t len; };

static void *touch_quad(void *arg)
{
	struct touch_quad *q = arg;
	for (size_t i = 0; i < q->len; i += 4096)
		q->base[i] = 1;
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "usage: %s PROVIDER K MIB\n", argv[0]);
		return 2;
	}
	int K = atoi(argv[2]);
	long mib = atol(argv[3]);
	if (K < 1 || K > 100000) {
		fprintf(stderr, "bad K\n");
		return 2;
	}
	if (mib < 0 || mib > 65536) {
		fprintf(stderr, "bad MIB\n");
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
	if (g(&l)) {
		fprintf(stderr, "gfl\n");
		return 1;
	}
	fns = (void **)((char *)l + 8);
	INITARGS a;
	memset(&a, 0, sizeof a);
	a.flags = 2;
	unsigned long init = 0, sl = 0, gi = 0, gsi = 0, gti = 0, failed = 0;
	if (F(0, CK_RV(*)(void *))(&a)) {
		fprintf(stderr, "init\n");
		return 1;
	}
	init = 1;
	CK_SLOT_ID slots[16];
	CK_ULONG ns = 16;
	if (F(4, CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(0, slots, &ns) || ns < 1) {
		fprintf(stderr, "slots\n");
		return 1;
	}
	sl = 1;
	if (mib > 0) {
		size_t n = (size_t)mib << 20;
		char *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) {
			fprintf(stderr, "NOMEM\n");
			return 3;
		}
		pthread_t th[4];
		struct touch_quad q[4];
		for (int t = 0; t < 4; t++) {
			q[t].base = p + (size_t)t * (n / 4);
			q[t].len = n / 4;
			if (pthread_create(&th[t], 0, touch_quad, &q[t])) {
				fprintf(stderr, "thread\n");
				return 1;
			}
		}
		for (int t = 0; t < 4; t++)
			pthread_join(th[t], 0);
	}
	printf("READY pid=%d\n", getpid());
	fflush(stdout);
	static unsigned char info[512];
	for (int k = 0; k < K; k++) {
		if (F(2, CK_RV(*)(void *))(info))
			failed++;
		else
			gi++;
		ns = 16;
		if (F(4, CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(0, slots, &ns))
			failed++;
		else
			sl++;
		if (F(5, CK_RV(*)(CK_SLOT_ID, void *))(slots[0], info))
			failed++;
		else
			gsi++;
		if (F(6, CK_RV(*)(CK_SLOT_ID, void *))(slots[0], info))
			failed++;
		else
			gti++;
	}
	printf("COUNTS init=%lu slotlist=%lu getinfo=%lu getslotinfo=%lu gettokeninfo=%lu failed=%lu\n",
	       init, sl, gi, gsi, gti, failed);
	fflush(stdout);
	for (;;)
		pause();
	return 0;
}
