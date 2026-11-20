/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* r071_holder: long-lived control caller. Map the provider, C_Initialize,
 * print READY, wait for the gate file, then run exactly POLLS
 * C_GetSlotList rounds POLL_MS apart printing POLL lines, print DONE,
 * and linger until killed. Cell (a) asserts every poll is counted:
 * the v0.7.1 regression drops polls of an admitted always-alive
 * process with zero residue.
 *
 * usage: r071_holder PROVIDER GATE POLLS POLL_MS
 * stdout: READY pid=%d, POLL i=%u, DONE polls=%u
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

static int gate_open(const char *gate)
{
	for (int i = 0; i < 6000; i++) {
		if (access(gate, F_OK) == 0)
			return 1;
		usleep(10000);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "usage: %s PROVIDER GATE POLLS POLL_MS\n", argv[0]);
		return 2;
	}
	long polls = atol(argv[3]);
	long poll_ms = atol(argv[4]);
	if (polls < 1 || polls > 100000 || poll_ms < 1 || poll_ms > 60000) {
		fprintf(stderr, "bad POLLS/POLL_MS\n");
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
	if (F(0, CK_RV(*)(void *))(&a)) {
		fprintf(stderr, "init\n");
		return 1;
	}
	CK_SLOT_ID slots[16];
	CK_ULONG ns = 16;
	if (F(4, CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(0, slots, &ns) || ns < 1) {
		fprintf(stderr, "slots\n");
		return 1;
	}
	printf("READY pid=%d\n", getpid());
	fflush(stdout);
	if (!gate_open(argv[2])) {
		fprintf(stderr, "gate never opened\n");
		return 1;
	}
	for (long i = 1; i <= polls; i++) {
		ns = 16;
		if (F(4, CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(0, slots, &ns)) {
			fprintf(stderr, "poll %ld failed\n", i);
			return 1;
		}
		printf("POLL i=%ld\n", i);
		fflush(stdout);
		usleep((useconds_t)(poll_ms * 1000));
	}
	printf("DONE polls=%ld\n", polls);
	fflush(stdout);
	for (;;)
		pause();
	return 0;
}
