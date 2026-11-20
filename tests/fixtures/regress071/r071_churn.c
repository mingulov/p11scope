/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* r071_churn: loader churn with zero PKCS#11 calls
 * (dlopen/dlsym-resolve/dlclose).
 * usage: r071_churn PROVIDER [SLEEP_US] */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	long su = argc > 2 ? atol(argv[2]) : 100;
	unsigned long it = 0, fail = 0;
	printf("CHURN pid=%d\n", getpid());
	fflush(stdout);

	time_t last = time(0);
	for (;;) {
		void *h = dlopen(argv[1], RTLD_NOW);
		if (!h) {
			fail++;
		} else {
			volatile void *s = dlsym(h, "C_GetFunctionList");
			(void)s;
			dlclose(h);
		}
		it++;
		if (su > 0)
			usleep((useconds_t)su);
		time_t now = time(0);
		if (now - last >= 30) {
			printf("CHURN_ALIVE iters=%lu fails=%lu\n", it, fail);
			fflush(stdout);
			last = now;
		}
	}
	return 0;
}
