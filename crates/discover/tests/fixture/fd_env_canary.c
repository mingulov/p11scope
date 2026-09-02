#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#define PLANTED_FD 17
typedef unsigned long CK_RV;
#ifdef DEPENDENCY
int fd_env_loader_marker(void) { return 1; }
#else
__attribute__((constructor)) static void ctor(void) {
    ssize_t n = write(PLANTED_FD, "LEAK", 4);
    fprintf(stderr, "CANARY_FD=%s\n", (n < 0 && errno == EBADF) ? "closed" : "OPEN");
    void *dep = dlopen("fd-env-dependency.so", RTLD_NOW | RTLD_LOCAL);
    void *preload = dlsym(RTLD_DEFAULT, "fd_env_loader_marker");
    fprintf(stderr, "CANARY_SEARCH=%s\n", dep ? "present" : "absent");
    fprintf(stderr, "CANARY_PRELOAD=%s\n", preload ? "present" : "absent");
    fflush(stderr);
}
CK_RV C_GetFunctionList(void **pp) { *pp = 0; return 5UL; /* CKR_GENERAL_ERROR */ }
#endif
