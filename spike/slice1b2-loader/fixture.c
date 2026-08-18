#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

static void mark(const char *s) {
    printf("%s pid=%ld\n", s, (long)getpid());
    fflush(stdout);
}

int main(void) {
    mark("LAUNCHER_BEFORE_DLOPEN");
    void *handle = dlopen("./libfixture.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        printf("DLOPEN_ERROR=%s\n", dlerror());
        return 1;
    }
    mark("LAUNCHER_AFTER_DLOPEN");
    sleep(1);
    if (dlclose(handle) != 0) {
        printf("DLCLOSE_ERROR=%s\n", dlerror());
        return 1;
    }
    mark("LAUNCHER_AFTER_DLCLOSE");
    return 0;
}
