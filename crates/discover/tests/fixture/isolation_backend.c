/* Lazy backend for the isolation probe fixture. Never DT_NEEDED by the
 * probe; the probe's C_GetFunctionList dlopen's it by bare name (resolved
 * through the probe's $ORIGIN rpath).
 */
typedef unsigned long CK_RV;

CK_RV isolation_backend_fn0(void) { return 0; }
CK_RV isolation_backend_fn1(void) { return 0; }
