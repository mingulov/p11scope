/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* r071_anchor: map the provider once and sleep, zero PKCS#11 calls.
 * Keeps the module mapped from capture start so attach settles
 * before counted children run.
 * usage: r071_anchor PROVIDER */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	printf("ANCHOR pid=%d\n", getpid());
	fflush(stdout);
	for (;;)
		pause();
	return 0;
}
