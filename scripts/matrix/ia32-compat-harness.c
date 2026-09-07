#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#ifdef IA32_COMPAT_DSO
static volatile unsigned long loaded;

__attribute__((constructor)) static void mark_loaded(void) {
    loaded = 1;
}
#else
typedef unsigned long (*probe_fn)(unsigned long, unsigned long, unsigned long,
                                  unsigned long, unsigned long, unsigned long,
                                  unsigned long);

static volatile unsigned long sink;

__attribute__((noinline, noclone, used, externally_visible, visibility("default")))
unsigned long abi_probe(unsigned long a0, unsigned long a1, unsigned long a2,
                        unsigned long a3, unsigned long a4, unsigned long a5,
                        unsigned long a6) {
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    (void)a6;
    __asm__ volatile("" ::: "memory");
#if __SIZEOF_LONG__ == 4
    return a0 == 1 ? 0UL : 0x80000001UL;
#else
    return a0 == 1 ? 0UL : 0x1234567880000001UL;
#endif
}

static probe_fn volatile call_probe = abi_probe;

int main(int argc, char **argv) {
    const unsigned int abi = sizeof(unsigned long) * 8;
    const int bystander = argc == 3 && strcmp(argv[2], "bystander") == 0;
    if (argc != 2 && !bystander) return 2;
    printf("FIXTURE_READY=%u\n", abi);
    fflush(stdout);
    if (!bystander && raise(SIGSTOP) != 0) return 3;

    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 4;
    if (dlclose(handle) != 0) return 5;
    sink ^= call_probe(1, 2, 3, 4, 5, 6, 7);
    sink ^= call_probe(11, 22, 33, 44, 55, 66, 77);

    printf("FIXTURE_DONE=%u\n", abi);
    return 0;
}
#endif
