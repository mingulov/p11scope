/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* G2 header-parity fixture: executes the actual native
 * `journal_header_valid` from crates/ebpf/native/object_journal.h over
 * the (length x kind x flags x identity) union and prints one verdict
 * line per combination for the Rust parity test to compare against the
 * real `validate_begin`/`validate_end`/`validate_abandon` verdicts.
 * Host-only; enables no production define or BPF load. A nonzero exit
 * means the native high-bit self-check below failed. */
#include "object_journal.h"

#include <stdio.h>

static const u64 parity_lengths[] = {
    0, 1, 63, 64, 65, 100, 223, 224, 225, 471, 472, 473, 631, 632, 633,
};
static const u64 parity_kinds[] = { 0, 1, 2, 3, 4, 9 };
static const u64 parity_identities[][2] = { { 0, 0 }, { 0, 7 }, { 7, 0 }, { 7, 7 } };
/* Native flag inputs wider than the u8 wire byte: the exact-match
 * validator must refuse every one of them on every header. */
static const u64 parity_wide_flags[] = {
    0x100ULL, 0x101ULL, 0x102ULL, 0x104ULL, 0x106ULL, 0x1ffULL,
    0x8000ULL, 0x10000ULL, 0xffffffffULL, 0x100000000ULL, 0xffffffffffffffffULL,
};

int main(void)
{
    size_t li, ki, ii;
    unsigned long flags;
    for (li = 0; li < sizeof(parity_lengths) / sizeof(parity_lengths[0]); li++) {
        for (ki = 0; ki < sizeof(parity_kinds) / sizeof(parity_kinds[0]); ki++) {
            for (flags = 0; flags <= 0xff; flags++) {
                for (ii = 0; ii < sizeof(parity_identities) /
                         sizeof(parity_identities[0]);
                     ii++) {
                    u64 thread = parity_identities[ii][0];
                    u64 sequence = parity_identities[ii][1];
                    int verdict = !!journal_header_valid(
                        parity_lengths[li], parity_kinds[ki], flags, 0,
                        thread, sequence);
                    printf("%llu %llu %lu %llu %llu %d\n",
                           (unsigned long long)parity_lengths[li],
                           (unsigned long long)parity_kinds[ki], flags,
                           (unsigned long long)thread,
                           (unsigned long long)sequence, verdict);
                }
            }
        }
    }
    /* Self-check: no wide flag value is ever accepted, on any
     * length/kind/identity. The Rust side has no counterpart for these
     * (the wire flags byte is u8); the exit status carries this pin. */
    for (li = 0; li < sizeof(parity_lengths) / sizeof(parity_lengths[0]); li++) {
        for (ki = 0; ki < sizeof(parity_kinds) / sizeof(parity_kinds[0]); ki++) {
            size_t wi;
            for (wi = 0; wi < sizeof(parity_wide_flags) /
                     sizeof(parity_wide_flags[0]);
                 wi++) {
                for (ii = 0; ii < sizeof(parity_identities) /
                         sizeof(parity_identities[0]);
                     ii++) {
                    if (journal_header_valid(
                            parity_lengths[li], parity_kinds[ki],
                            parity_wide_flags[wi], 0,
                            parity_identities[ii][0],
                            parity_identities[ii][1])) {
                        fprintf(stderr,
                                "wide flags %llu accepted on %llu/%llu\n",
                                (unsigned long long)parity_wide_flags[wi],
                                (unsigned long long)parity_lengths[li],
                                (unsigned long long)parity_kinds[ki]);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
