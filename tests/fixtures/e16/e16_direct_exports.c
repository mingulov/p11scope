/* SPDX-License-Identifier: GPL-3.0-or-later */
/* E16 surface: direct PKCS#11 exports without any discoverable table.
 *
 * This provider exports a handful of PKCS#11 entry points directly as
 * dynamic symbols but publishes no factory (no C_GetFunctionList / C_GetInterfaceList / C_GetInterface /
 * NSC_ / FC_ variants) and holds no function table anywhere in memory.
 * From discovery's view this is the same shape as an inlined wrapper:
 * executable PKCS#11 code with no table to decode.
 *
 * Every export shares one NULL-tolerant `CK_RV name(void *)` shape. These
 * toy one-argument stubs establish the execution shape only, not PKCS#11
 * ABI or semantic conformance. Each emits a truth line unless
 * P11SCOPE_E16_QUIET=1:
 *   P11SCOPE_E16 provider direct <name>
 *
 * Build: gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
 *            -o e16_direct_exports.so e16_direct_exports.c
 */

#include "e16_protocol.h"

typedef unsigned long CK_RV;

#define CKR_OK 0UL

#define PROVIDER_EXPORT __attribute__((visibility("default")))

static void emit_provider(const char *name) {
    e16_provider_witness("direct", name);
}

#define DIRECT_EXPORT(name)                                \
    PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV \
    name(void *arg) {                                     \
        (void)arg;                                        \
        emit_provider(#name);                             \
        return CKR_OK;                                    \
    }

DIRECT_EXPORT(C_Initialize)
DIRECT_EXPORT(C_Finalize)
DIRECT_EXPORT(C_GetInfo)
DIRECT_EXPORT(C_GetSlotList)
DIRECT_EXPORT(C_GenerateRandom)
