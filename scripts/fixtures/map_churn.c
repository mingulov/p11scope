/* SPDX-License-Identifier: GPL-3.0-or-later */
/* map_churn: self-timed file-mapping churn for the Stage A overhead gate.
 * usage: map_churn FILE OPS MODE
 * MODE mmap: OPS x {mmap 4096 PROT_READ MAP_PRIVATE, munmap} of FILE.
 * MODE mremap: one 2-page mapping of FILE, then OPS x MREMAP_FIXED ping-pong
 * of its first page between the two page slots (each mremap reaches copy_vma
 * plus the old VMA's uprobe_munmap), then unmap. OPS must be even.
 * Times only the loop with CLOCK_MONOTONIC and prints one line:
 *   MAP_CHURN ops=N wall_ns=T mode=M file=F
 * Exit nonzero (with FAIL on stderr) on any shortfall, so a sample that did
 * not run exactly OPS operations can never be mistaken for a measurement. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        fprintf(stderr, "FAIL clock\n");
        exit(1);
    }
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static void churn_mmap(int fd, long ops)
{
    uint64_t start = now_ns();

    for (long i = 0; i < ops; i++) {
        void *page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (page == MAP_FAILED) {
            fprintf(stderr, "FAIL mmap %ld\n", i);
            exit(1);
        }
        if (munmap(page, 4096) != 0) {
            fprintf(stderr, "FAIL munmap %ld\n", i);
            exit(1);
        }
    }
    printf("MAP_CHURN ops=%ld wall_ns=%lu mode=mmap\n", ops, (unsigned long)(now_ns() - start));
}

static void churn_mremap(int fd, long ops)
{
    void *base;
    void *first;
    void *second;
    uint64_t start;

    /* Two adjacent pages; the second slot starts unmapped so the FIXED
     * target is always free. */
    base = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        fprintf(stderr, "FAIL mmap base\n");
        exit(1);
    }
    first = base;
    second = (char *)base + 4096;
    if (munmap(second, 4096) != 0) {
        fprintf(stderr, "FAIL munmap second\n");
        exit(1);
    }
    start = now_ns();
    for (long i = 0; i < ops; i += 2) {
        void *moved = mremap(first, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, second);
        if (moved == MAP_FAILED) {
            fprintf(stderr, "FAIL mremap %ld forward\n", i);
            exit(1);
        }
        moved = mremap(second, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, first);
        if (moved == MAP_FAILED) {
            fprintf(stderr, "FAIL mremap %ld back\n", i);
            exit(1);
        }
    }
    printf("MAP_CHURN ops=%ld wall_ns=%lu mode=mremap\n", ops, (unsigned long)(now_ns() - start));
    if (munmap(first, 4096) != 0) {
        fprintf(stderr, "FAIL munmap first\n");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    const char *mode;
    char *end = NULL;
    long ops;
    int fd;

    if (argc != 4) {
        fprintf(stderr, "usage: map_churn FILE OPS MODE\n");
        return 2;
    }
    ops = strtol(argv[2], &end, 10);
    if (!end || *end || ops <= 0) {
        fprintf(stderr, "usage: OPS is a positive integer\n");
        return 2;
    }
    mode = argv[3];
    if (strcmp(mode, "mremap") == 0 && ops % 2 != 0) {
        fprintf(stderr, "usage: mremap OPS is even\n");
        return 2;
    }
    if (strcmp(mode, "mmap") != 0 && strcmp(mode, "mremap") != 0) {
        fprintf(stderr, "usage: MODE is mmap or mremap\n");
        return 2;
    }
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "FAIL open %s\n", argv[1]);
        return 1;
    }
    if (strcmp(mode, "mmap") == 0)
        churn_mmap(fd, ops);
    else
        churn_mremap(fd, ops);
    close(fd);
    return 0;
}
