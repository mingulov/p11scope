typedef unsigned char CK_BYTE;
typedef unsigned long CK_RV;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { CK_VERSION version; void *functions[68]; } Table;

static CK_RV backend_function(void) { return 0; }

void *backend_table(void) {
    static Table table;
    static int initialized;
    if (!initialized) {
        initialized = 1;
        table.version = (CK_VERSION){2, 40};
        for (int i = 0; i < 68; i++) table.functions[i] = (void *)backend_function;
    }
    return &table;
}
