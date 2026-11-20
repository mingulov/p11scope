/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* r071_inv_child: map the provider, sleep WAIT_S so scan admission can
 * bind the mapping BEFORE any call, then C_Initialize, one
 * C_GetSlotList, K counted call rounds, C_Finalize, print COUNTS,
 * linger LINGER_S so the exit spans a scan pass, and exit 0. Cell (c)
 * streams these at 1/s and asserts the driver's entry totals are
 * counted. Expected entries per child: 3 + 4*K (init + slotlist +
 * finalize + K getinfo/slotlist/getslotinfo/gettokeninfo rounds).
 *
 * usage: r071_inv_child PROVIDER K WAIT_S LINGER_S
 * stdout: COUNTS init=.. slotlist=.. getinfo=.. getslotinfo=..
 *   gettokeninfo=.. finalize=.. failed=..
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID;
typedef struct { void *c, *d, *l, *u; unsigned long flags; void *r; } INITARGS;
#define F(i, t) ((t)fns[i])
static void **fns;

int main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "usage: %s PROVIDER K WAIT_S LINGER_S\n", argv[0]);
		return 2;
	}
	int K = atoi(argv[2]);
	int wait_s = atoi(argv[3]);
	int linger_s = atoi(argv[4]);
	if (K < 1 || K > 100000 || wait_s < 0 || wait_s > 300 || linger_s < 0 || linger_s > 300) {
		fprintf(stderr, "bad K/WAIT/LINGER\n");
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
	if (wait_s > 0)
		sleep((unsigned)wait_s);
	INITARGS a;
	memset(&a, 0, sizeof a);
	a.flags = 2;
	unsigned long init = 0, sl = 0, gi = 0, gsi = 0, gti = 0, fin = 0, failed = 0;
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
	if (F(1, CK_RV(*)(void *))(0))
		failed++;
	else
		fin = 1;
	printf("COUNTS init=%lu slotlist=%lu getinfo=%lu getslotinfo=%lu gettokeninfo=%lu finalize=%lu failed=%lu\n",
	       init, sl, gi, gsi, gti, fin, failed);
	fflush(stdout);
	if (failed)
		return 1;
	if (linger_s > 0)
		sleep((unsigned)linger_s);
	return 0;
}
