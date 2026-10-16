/* SPDX-License-Identifier: GPL-3.0-or-later */
/* H8-D birth-row publisher: runs the REAL marker leaves over real
 * instance_record rows and dumps the resulting NATIVE bytes for the
 * Rust birth-observation tests, so happy paths traverse genuinely
 * published rows (never hand-built words). Only the argv parameters
 * are injected; every dumped byte comes from the production
 * publication/dirty/admission implementation. Inactive: no live root
 * calls these leaves.
 *
 * Usage: birth_row_publisher <exec> [admit-count] [dirty] [admit-exec] [nopub] [gen]
 *   exec:        publication exec id (0 allowed: READY(0) is word 2)
 *   admit-count: admission attempts (each a real admit() call)
 *   dirty:       nonzero runs the real dirty() leaf after publication
 *   admit-exec:  exec id the admit() calls present (default: exec; a
 *                mismatch trips the failed latch natively)
 *   nopub:       nonzero skips publication (dumps the unmarked row;
 *                dirty still applies, so nopub+dirty dumps DIRTY)
 *   gen:         exec_attach_gen word to stamp (default 0). Argv-settled:
 *                it models the BPF exec-stamp from the attach cell (the
 *                stamp itself is covered in instance_epoch); what the
 *                Rust observation tests pin is the generation comparison,
 *                not this word's provenance.
 * Output:
 *   ROW <152 bytes as hex>
 *   CTL <16 bytes as hex>
 *   WINS <admitted count> */
#define P11SCOPE_JOURNAL_MARKER_NO_MAPS
#include "journal_marker.h"
#include "journal_marker.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void dump_hex(const char *tag, const unsigned char *bytes, unsigned len)
{
    unsigned i;
    printf("%s ", tag);
    for (i = 0; i < len; i++)
        printf("%02x", bytes[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    static struct instance_record rec;
    static struct journal_admission_control ctl;
    unsigned long exec, admits, dirty, admit_exec, nopub, i, wins;
    unsigned long long gen;

    if (argc < 2 || argc > 7) {
        fprintf(stderr,
                "usage: %s <exec> [admit-count] [dirty] [admit-exec] [nopub] [gen]\n",
                argv[0]);
        return 2;
    }
    exec = strtoul(argv[1], 0, 0);
    admits = (argc > 2) ? strtoul(argv[2], 0, 0) : 0;
    dirty = (argc > 3) ? strtoul(argv[3], 0, 0) : 0;
    admit_exec = (argc > 4) ? strtoul(argv[4], 0, 0) : exec;
    nopub = (argc > 5) ? strtoul(argv[5], 0, 0) : 0;
    gen = (argc > 6) ? strtoull(argv[6], 0, 0) : 0;
    if (exec > 0x3fffffffffffffffUL || admit_exec > 0x3fffffffffffffffUL)
        return 2;
    memset(&rec, 0, sizeof(rec));
    memset(&ctl, 0, sizeof(ctl));
    /* The argv-settled exec stamp (see the header comment). */
    rec.exec_attach_gen = (u64)gen;
    if (!nopub && !p11_journal_marker_publish(&rec, (u64)exec)) {
        fprintf(stderr, "publish refused\n");
        return 1;
    }
    if (dirty)
        p11_journal_marker_dirty(&rec);
    wins = 0;
    for (i = 0; i < admits; i++)
        wins += (unsigned)p11_journal_marker_admit(&ctl, rec.journal_bootstrap,
                                                   (u64)admit_exec);
    dump_hex("ROW", (const unsigned char *)&rec, sizeof(rec));
    dump_hex("CTL", (const unsigned char *)&ctl, sizeof(ctl));
    printf("WINS %lu\n", wins);
    return 0;
}
