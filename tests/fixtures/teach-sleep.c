/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Teach-preload for verify-unidentified-exe-name.sh --teach: sleep in a
 * constructor so a preloaded tool instance stays alive (with its exe
 * path intact) while the observer admits it. Admission records the
 * teacher's path, and the scan-learned map then resolves the pair for
 * every short-lived run of the same binary — the measured runs need
 * no live /proc of their own. The exe stays the tool: only its
 * lifetime changes. Build: cc -shared -fPIC -O2 -o teach_sleep.so
 * teach-sleep.c
 *
 * Linger-preload for --linger: sleep in a destructor so a measured
 * run stays alive after its own main returns (its calls are already
 * staged) while the EXEC backfill reads its live /proc identity.
 * This names callers whose path never resolves on the host (a
 * container binary) through the live-process source. Build with
 * -DLINGER -o linger.so.
 */
#include <unistd.h>

#ifdef LINGER
__attribute__((destructor)) static void linger_wait(void) {
    sleep(20);
}
#else
__attribute__((constructor)) static void teach_wait(void) {
    sleep(120);
}
#endif
