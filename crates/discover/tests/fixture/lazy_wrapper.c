#include <dlfcn.h>

typedef unsigned long CK_RV;
typedef void *(*backend_table_fn)(void);

CK_RV C_GetFunctionList(void **out) {
    if (!out) return 7;
    void *library = dlopen("lazy-backend.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) return 5;
    backend_table_fn table = (backend_table_fn)dlsym(library, "backend_table");
    if (!table) return 5;
    *out = table();
    return 0;
}
