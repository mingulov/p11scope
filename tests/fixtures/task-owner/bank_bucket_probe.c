/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Host probe: runs the actual bank_bucket() from the timing bank producer
 * over argv-supplied hex inputs, printing one bucket index per line. The
 * Rust boundary test compares each line against
 * p11scope_ebpf_common::bucket_of. The probe never routes or touches
 * START, so the producer's owner constructors stay stubbed. */

/* Map identities referenced by the producer body. */
unsigned char COUNTER_HEALTH, RV_COUNTS;

/* The producer (through task_owner.h) defines __always_inline itself, so
 * it precedes the system headers exactly like helper_tests.c does. */
#include "counter_bank_timing.c"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* Owner constructors referenced by the producer body, never called here. */
u32 p11_owner_start_aggregate(const struct owner_start_key *key, u64 timestamp)
{
    (void)key;
    (void)timestamp;
    assert(!"bucket probe never touches START");
    return 0;
}

void *p11_owner_start_get(const struct owner_start_key *key, u32 required)
{
    (void)key;
    (void)required;
    assert(!"bucket probe never touches START");
    return (void *)0;
}

long p11_owner_start_remove(const struct owner_start_key *key, u32 required)
{
    (void)key;
    (void)required;
    assert(!"bucket probe never touches START");
    return 0;
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        char *end = (char *)0;
        unsigned long long delta = strtoull(argv[i], &end, 16);
        if (!end || *end) {
            fprintf(stderr, "bad hex input: %s\n", argv[i]);
            return 2;
        }
        printf("%u\n", bank_bucket((u64)delta));
    }
    return 0;
}
