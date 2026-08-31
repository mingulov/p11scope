/* Slice 1b-2 production live-discovery driver fixture.
 *
 * One source, three frozen builds; the provider byte identities it drives are
 * used unchanged by both load kinds:
 *
 *   DT_NEEDED: gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC \
 *                  -DP11SCOPE_DRIVER_NEEDED=1 -o driver-needed-exported \
 *                  live-discovery-driver.c /abs/provider-exported.so \
 *                  -ldl -pthread          (and the same against the hidden .so)
 *   dlopen:    gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC \
 *                  -o driver-dlopen live-discovery-driver.c -ldl -pthread
 *
 * The .so is linked by absolute path, so DT_NEEDED records that exact file and
 * no search path can substitute another provider.
 *
 *   driver <mode> [provider.so ...]
 *     needed        provider already mapped at exec (initial_set load kind)
 *     dlopen        dlopen every argument in order (dlopen load kind)
 *     pause-partial dlopen the first argument on the main thread and the last
 *                   one from a second thread, so a lane can observe one closed
 *                   and one partial pause window
 *     exec-fail     exec a path that cannot exist (child exec failure lane)
 *     zero-modules  load nothing at all (zero-modules lane)
 *
 * Environment:
 *   P11SCOPE_FIXTURE_GATE=1     read one byte from stdin before doing anything,
 *                               so an external-PID lane can attach first
 *   P11SCOPE_FIXTURE_POST_GATE=1
 *                               emit the done marker after successful calls,
 *                               then read one byte before exiting
 *   P11SCOPE_FIXTURE_REPEAT=N   call every surface N times (loss lanes)
 *   P11SCOPE_FIXTURE_INTERFACES=N
 *                               use exactly N interface records for N in
 *                               {0, 1, 16, 17}; absent/invalid values use 1.
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;

typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;
typedef CK_INTERFACE *CK_INTERFACE_PTR;
typedef CK_INTERFACE_PTR *CK_INTERFACE_PTR_PTR;

#define P11SCOPE_FIXTURE_MAX_INTERFACES 17

typedef CK_RV (*get_function_list_fn)(void **);
typedef CK_RV (*get_interface_list_fn)(CK_INTERFACE *, CK_ULONG *);
typedef CK_RV (*get_interface_fn)(void *, void *, CK_INTERFACE_PTR_PTR, CK_FLAGS);

#define EXIT_USAGE 2
#define EXIT_GATE 3
#define EXIT_DLOPEN 4
#define EXIT_DLSYM 5
#define EXIT_SURFACE 6
#define EXIT_THREAD 7
#define EXIT_EXEC_FAILED 8

static void emit(const char *text) {
    ssize_t written = write(STDERR_FILENO, text, strlen(text));
    (void)written;
}

static long repeat_count(void) {
    const char *value = getenv("P11SCOPE_FIXTURE_REPEAT");
    if (value == NULL) {
        return 1;
    }
    long parsed = strtol(value, NULL, 10);
    return parsed > 0 ? parsed : 1;
}

static CK_ULONG fixture_interface_count(void) {
    const char *value = getenv("P11SCOPE_FIXTURE_INTERFACES");
    if (value != NULL) {
        if (strcmp(value, "0") == 0) {
            return 0;
        }
        if (strcmp(value, "1") == 0) {
            return 1;
        }
        if (strcmp(value, "16") == 0) {
            return 16;
        }
        if (strcmp(value, "17") == 0) {
            return 17;
        }
    }
    return 1;
}

struct provider_surfaces {
    get_function_list_fn get_function_list;
    get_interface_list_fn get_interface_list;
    get_interface_fn get_interface;
};

/* Calls all three standard return ABIs, in a fixed order, `repeat` times. */
static int drive(struct provider_surfaces surfaces, long repeat) {
    CK_ULONG expected = fixture_interface_count();
    for (long index = 0; index < repeat; index++) {
        void *table = NULL;
        if (surfaces.get_function_list(&table) != 0 || table == NULL) {
            return EXIT_SURFACE;
        }
        CK_INTERFACE interfaces[P11SCOPE_FIXTURE_MAX_INTERFACES];
        CK_ULONG count = P11SCOPE_FIXTURE_MAX_INTERFACES;
        if (surfaces.get_interface_list(interfaces, &count) != 0 || count != expected) {
            return EXIT_SURFACE;
        }
        if (expected != 0) {
            CK_INTERFACE_PTR interface = NULL;
            if (surfaces.get_interface(NULL, NULL, &interface, 0) != 0 ||
                interface == NULL || interface->pInterfaceName == NULL ||
                strcmp(interface->pInterfaceName, "PKCS 11") != 0 ||
                interface->pFunctionList == NULL || interface->flags != 0) {
                return EXIT_SURFACE;
            }
        }
    }
    return 0;
}

#if defined(P11SCOPE_DRIVER_NEEDED)
extern CK_RV C_GetFunctionList(void **out);
extern CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count);
extern CK_RV C_GetInterface(void *name, void *version, CK_INTERFACE_PTR_PTR out,
                            CK_FLAGS flags);
#endif

static int drive_dlopened(const char *path, long repeat) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        emit("P11SCOPE_FIXTURE driver dlopen-failed\n");
        return EXIT_DLOPEN;
    }
    struct provider_surfaces surfaces;
    surfaces.get_function_list = (get_function_list_fn)dlsym(handle, "C_GetFunctionList");
    surfaces.get_interface_list = (get_interface_list_fn)dlsym(handle, "C_GetInterfaceList");
    surfaces.get_interface = (get_interface_fn)dlsym(handle, "C_GetInterface");
    if (surfaces.get_function_list == NULL || surfaces.get_interface_list == NULL ||
        surfaces.get_interface == NULL) {
        emit("P11SCOPE_FIXTURE driver dlsym-failed\n");
        return EXIT_DLSYM;
    }
    emit("P11SCOPE_FIXTURE driver loaded\n");
    return drive(surfaces, repeat);
}

struct thread_load {
    const char *path;
    long repeat;
    int status;
};

static void *thread_main(void *argument) {
    struct thread_load *load = (struct thread_load *)argument;
    load->status = drive_dlopened(load->path, load->repeat);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return EXIT_USAGE;
    }
    const char *mode = argv[1];
    const char *gate = getenv("P11SCOPE_FIXTURE_GATE");
    if (gate != NULL && gate[0] == '1') {
        unsigned char byte = 0;
        if (read(STDIN_FILENO, &byte, 1) != 1) {
            return EXIT_GATE;
        }
    }
    long repeat = repeat_count();
    emit("P11SCOPE_FIXTURE driver start\n");

    int status = 0;
    if (strcmp(mode, "zero-modules") == 0) {
        if (argc != 2) {
            return EXIT_USAGE;
        }
    } else if (strcmp(mode, "exec-fail") == 0) {
        if (argc != 2) {
            return EXIT_USAGE;
        }
        char *const command[] = {(char *)"/nonexistent/p11scope-live-discovery-exec", NULL};
        execv(command[0], command);
        emit("P11SCOPE_FIXTURE driver exec-failed\n");
        return EXIT_EXEC_FAILED;
    } else if (strcmp(mode, "needed") == 0) {
#if defined(P11SCOPE_DRIVER_NEEDED)
        if (argc != 2) {
            return EXIT_USAGE;
        }
        struct provider_surfaces surfaces = {C_GetFunctionList, C_GetInterfaceList,
                                             C_GetInterface};
        emit("P11SCOPE_FIXTURE driver loaded\n");
        status = drive(surfaces, repeat);
#else
        return EXIT_USAGE;
#endif
    } else if (strcmp(mode, "dlopen") == 0) {
        if (argc < 3) {
            return EXIT_USAGE;
        }
        for (int index = 2; index < argc && status == 0; index++) {
            status = drive_dlopened(argv[index], repeat);
        }
    } else if (strcmp(mode, "pause-partial") == 0) {
        if (argc < 4) {
            return EXIT_USAGE;
        }
        status = drive_dlopened(argv[2], repeat);
        if (status == 0) {
            struct thread_load load = {argv[argc - 1], repeat, 0};
            pthread_t thread;
            if (pthread_create(&thread, NULL, thread_main, &load) != 0) {
                return EXIT_THREAD;
            }
            if (pthread_join(thread, NULL) != 0) {
                return EXIT_THREAD;
            }
            status = load.status;
        }
    } else {
        return EXIT_USAGE;
    }

    if (status != 0) {
        return status;
    }
    emit("P11SCOPE_FIXTURE driver done\n");
    const char *post_gate = getenv("P11SCOPE_FIXTURE_POST_GATE");
    if (post_gate != NULL && post_gate[0] == '1') {
        unsigned char byte = 0;
        if (read(STDIN_FILENO, &byte, 1) != 1) {
            return EXIT_GATE;
        }
    }
    return 0;
}
