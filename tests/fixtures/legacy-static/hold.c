/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned legacy-static holder (system-scale plan Task 1.5 case 9). Loads
 * the legacy-static provider, publishes its table through the real
 * C_GetFunctionList, prints the table exactly as the observer's probe
 * would capture it, makes the scripted calls, then waits for one stdin
 * line so the capture test can scan and publish against the live
 * process before releasing it.
 *
 * Usage: lshold <provider.so> <logpath> <ord,ord,...>
 *
 * Output: LSHOLD pid=<pid>, one PUBLISH block (TABLE index=-1 + 68 E
 * lines with dladdr symbols), one CALL line per scripted ordinal, then
 * READY. Any stdin line (or EOF) exits 0.
 *
 * Build: gcc -std=c11 -O2 -Wall -Wextra -Werror -o lshold hold.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef CK_RV (*EntryFn)(CK_ULONG p0, CK_ULONG p1);

#define CKR_OK 0UL
#define NENTRY 68

#define EXIT_USAGE 2
#define EXIT_LOAD 3
#define EXIT_SCENARIO 4

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: lshold <provider.so> <log> <ord,...>\n");
        return EXIT_USAGE;
    }
    if (setenv("P11SCOPE_MW_LOG", argv[2], 1) != 0) {
        fprintf(stderr, "lshold: setenv failed\n");
        return EXIT_LOAD;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "lshold: dlopen failed: %s\n", dlerror());
        return EXIT_LOAD;
    }
    dlerror();
    CK_RV (*gfl)(void **list) = dlsym(handle, "C_GetFunctionList");
    const char *err = dlerror();
    if (err != NULL || gfl == NULL) {
        fprintf(stderr, "lshold: missing C_GetFunctionList\n");
        return EXIT_LOAD;
    }
    void *table = NULL;
    if (gfl(&table) != CKR_OK || table == NULL) {
        fprintf(stderr, "lshold: C_GetFunctionList failed\n");
        return EXIT_SCENARIO;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("LSHOLD pid=%d\n", (int)getpid());
    const unsigned char *bytes = table;
    printf("PUBLISH begin count=1\n");
    printf("TABLE index=-1 addr=%p major=%u minor=%u nentry=%d\n", table, bytes[0], bytes[1],
        NENTRY);
    void *const *funcs = (void *const *)((const char *)table + 8);
    for (int o = 0; o < NENTRY; o++) {
        Dl_info info;
        const char *sym = "-";
        if (funcs[o] != NULL && dladdr((void *)funcs[o], &info) != 0
            && info.dli_sname != NULL) {
            sym = info.dli_sname;
        }
        printf("E ord=%d addr=%p sym=%s\n", o, funcs[o], sym);
    }
    printf("PUBLISH end\n");
    char *spec = argv[3];
    for (char *tok = strtok(spec, ","); tok != NULL; tok = strtok(NULL, ",")) {
        char *end = NULL;
        long ord = strtol(tok, &end, 10);
        if (end == tok || *end != '\0' || ord < 0 || ord >= NENTRY || funcs[ord] == NULL) {
            fprintf(stderr, "lshold: bad ordinal %s\n", tok);
            return EXIT_SCENARIO;
        }
        EntryFn fn = (EntryFn)funcs[ord];
        CK_RV rv = fn(0, 0);
        printf("CALL ord=%ld rv=%lu\n", ord, rv);
    }
    printf("READY\n");
    fflush(stdout);
    char *line = NULL;
    size_t cap = 0;
    if (getline(&line, &cap, stdin) < 0 && ferror(stdin)) {
        fprintf(stderr, "lshold: stdin read failed\n");
        free(line);
        return EXIT_SCENARIO;
    }
    free(line);
    dlclose(handle);
    return 0;
}
