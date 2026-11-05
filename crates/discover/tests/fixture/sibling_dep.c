/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Sibling dependency fixture for the provider-directory fallback: the
 * provider under test links against this library (DT_NEEDED) and the
 * library lives beside the provider, outside the loader search path. */
typedef unsigned long CK_RV;
CK_RV sibling_helper(void) { return 0UL; }
