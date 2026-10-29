/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Test adapter only. Native custody and BEGIN/return/settlement are the
 * production implementation included by the unchanged historical fixture.
 * Rust drives the same in-place return writers used by the private roots. */
#define main historical_journal_fixture_main
#include "journal_owner_tests.c"
#undef main

static struct journal_entry_context roots_context;
static void *roots_records[16];
static u32 roots_lengths[16], roots_count;
static u32 roots_continuity_consumes;
static int roots_fail_reserve_once;
static u32 roots_route_counts[3], roots_route_next;

static void roots_submit_hook(void *record, u64 flags)
{
    const unsigned char *bytes = record;
    assert(roots_count < 16);
    roots_records[roots_count] = record;
    roots_lengths[roots_count++] = (u32)bytes[2] | ((u32)bytes[3] << 8);
    /* The existing callback asserts all three rows are absent for END and
     * ABANDON. Keep that check at the actual native submission boundary. */
    ring_submit(record, flags);
}

static void roots_discard_hook(void *record, u64 flags)
{
    (void)flags;
    assert(record);
    /* The root reports ring, unmatched-return or semantic loss before a
     * discard. Unlike the old combined fixture this also permits the real
     * root's unmatched-return evidence cell. */
    assert(producer_gaps && (producer_evidence[0] || producer_evidence[2] || producer_evidence[5]));
    ring_discards++;
}

void roots_setup(u32 descriptor, u32 class_bits, u32 layout, u32 object, u32 session_arg)
{
    failures = 0;
    roots_context = producer_setup(descriptor, class_bits, object, (unsigned char)session_arg);
    roots_context.layout = layout;
    if (object) {
        struct object_start *side = lookup(&OBJECT_START, &producer_terminal_key);
        assert(side);
        side->layout = layout;
    }
    roots_count = roots_continuity_consumes = 0;
    roots_fail_reserve_once = 0;
    memset(roots_route_counts, 0, sizeof(roots_route_counts));
    roots_route_next = 0;
    journal_ring_submit = roots_submit_hook;
    journal_ring_discard = roots_discard_hook;
}

void *roots_row(u32 kind)
{
    switch (kind) {
    case 0: return lookup(&START, &producer_terminal_key);
    case 1: return lookup(&OBJECT_START, &producer_terminal_key);
    case 2: return lookup(&INSTANCE_START, &producer_terminal_key);
    case 3: return &producer_terminal_key;
    case 4: return &roots_context;
    default: return NULL;
    }
}

void roots_object_descriptor(const void *descriptor)
{
    assert(descriptor);
    assert(!update(&OBJECT_DESCRIPTORS, &roots_context.descriptor, descriptor, 0));
}

void roots_begin(const struct journal_entry_context *context)
{
    assert(context);
    p11_journal_begin(&producer_terminal_key, context);
}

void roots_returning(struct journal_return_words *words)
{
    p11_journal_returning(&producer_terminal_key, words);
}

long roots_remove(u32 reason)
{
    return p11_owner_start_remove_reason(&producer_terminal_key, 1, reason);
}

u32 roots_cleanup(void)
{
    return p11_owner_cleanup();
}

void roots_aggregate(void)
{
    reset();
    failures = 0;
    producer_mode = 1;
    roots_count = roots_continuity_consumes = 0;
    memset(roots_route_counts, 0, sizeof(roots_route_counts));
    roots_route_next = 0;
    producer_terminal_key = (struct owner_start_key){ .pid_tgid = pid_tgid(), .slot = 5 };
    seed_object_tables();
    assert(p11_owner_start_aggregate(&producer_terminal_key, 123) == 1);
    journal_ring_submit = roots_submit_hook;
    journal_ring_discard = roots_discard_hook;
}

void roots_fail(u32 flags)
{
    fail_reserve = !!(flags & (1 | 64));
    roots_fail_reserve_once = !!(flags & 64);
    fail_journal_delete = !!(flags & 2);
    producer_object_delete_fail = !!(flags & 4);
    producer_start_delete_fail = !!(flags & 8);
    producer_phase_fail = !!(flags & 16);
    producer_insert_fail = !!(flags & 32);
}

void roots_loss(u32 index)
{
    assert(index < 6);
    (void)p11_instance_scope_gap();
    producer_evidence[index]++;
}

void *roots_reserve(u32 bytes)
{
    void *record = p11_journal_reserve(&EVENTS, bytes);
    if (roots_fail_reserve_once) {
        roots_fail_reserve_once = 0;
        fail_reserve = 0;
    }
    return record;
}

void roots_submit(void *record)
{
    p11_journal_submit(record);
}

void roots_discard(void *record)
{
    p11_journal_discard(record);
}

u64 roots_routing(u32 word)
{
    assert(word < 3 && word == roots_route_next);
    roots_route_next++;
    roots_route_counts[word]++;
    return word == 0 ? producer_terminal_key.pid_tgid : 1;
}

/* Controlled continuity facts come from the independent retained row, not
 * from BEGIN. This adapter consumes it once, like the actual native return
 * helper; ELF reachability separately pins the real helper in the roots.
 * `joined == 0` models the independently sampled return stamp refusing. */
void roots_continuity(void *output, u32 joined)
{
    struct journal_entry_witness *entry = lookup(&INSTANCE_START, &producer_terminal_key);
    unsigned char *bytes = output;
    assert(entry && output);
    memcpy(bytes, entry, 24);
    memcpy(bytes + 24, entry->entry_stamp, 16);
    if (!joined)
        memset(bytes + 24, 0, 16);
    assert(!pair_delete(&INSTANCE_START, &producer_terminal_key));
    roots_continuity_consumes++;
}

void *roots_record(u32 index, u32 *length)
{
    if (index >= roots_count)
        return NULL;
    *length = roots_lengths[index];
    return roots_records[index];
}

void roots_status(u64 *words)
{
    words[0] = lookup(&START, &producer_terminal_key) != NULL;
    words[1] = lookup(&OBJECT_START, &producer_terminal_key) != NULL;
    words[2] = lookup(&JOURNAL_START, &producer_terminal_key) != NULL;
    words[3] = owners[current_index].flags != 0;
    words[4] = ctl.outstanding;
    words[5] = ring_submits;
    words[6] = ring_discards;
    words[7] = producer_gaps;
    words[8] = producer_evidence[0];
    words[9] = producer_evidence[5];
    words[10] = failures;
    words[11] = roots_continuity_consumes;
    words[12] = roots_route_counts[0];
    words[13] = roots_route_counts[1];
    words[14] = roots_route_counts[2];
}

#ifdef P11_JOURNAL_ROOTS_PREPARE_TEST
#include <sys/resource.h>

static void roots_header_poison_controls(void)
{
    static const struct {
        struct journal_header_spec spec;
        int valid;
    } cases[] = {
        {{224, 1, 0, 7, 3}, 1}, {{224, 1, 1, 7, 3}, 1},
        {{632, 2, 0, 7, 3}, 1}, {{632, 2, 2, 7, 3}, 1},
        {{472, 2, 0, 7, 3}, 1}, {{472, 2, 2, 7, 3}, 1},
        {{64, 3, 0, 7, 3}, 1},
        {{224, 1, 0, 0, 3}, 0}, {{224, 1, 0, 7, 0}, 0},
        {{223, 1, 0, 7, 3}, 0}, {{632, 1, 0, 7, 3}, 0},
        {{224, 0, 0, 7, 3}, 0}, {{224, 4, 0, 7, 3}, 0},
        {{224, 1, 4, 7, 3}, 0}, {{224, 1, 2, 7, 3}, 0},
        {{632, 2, 1, 7, 3}, 0}, {{632, 2, 4, 7, 3}, 0},
        {{64, 3, 1, 7, 3}, 0}, {{63, 3, 0, 7, 3}, 0},
        {{633, 2, 0, 7, 3}, 0}, {{64, 3, 0x100, 7, 3}, 0},
        {{64, 0x103, 0, 7, 3}, 0}, {{0x10040, 3, 0, 7, 3}, 0},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        unsigned char expected[32], actual[32];
        const struct journal_header_spec *spec = &cases[i].spec;
        memset(expected, 0xa5, sizeof(expected));
        if (cases[i].valid) {
            memset(expected, 0, 24);
            expected[0] = 1;
            expected[2] = spec->bytes & 0xff;
            expected[3] = spec->bytes >> 8;
            expected[4] = spec->kind;
            expected[5] = spec->flags;
            memcpy(expected + 8, &spec->thread, 8);
            memcpy(expected + 16, &spec->sequence, 8);
        }
        memset(actual, 0xa5, sizeof(actual));
        assert(p11_journal_header_init(actual, spec) == (cases[i].valid ? 0 : -1));
        assert(!memcmp(actual, expected, sizeof(actual)));
        memset(actual, 0xa5, sizeof(actual));
        assert(journal_header_write(actual, spec->bytes, spec->kind, spec->flags,
                                      spec->thread, spec->sequence) == (cases[i].valid ? 0 : -1));
        assert(!memcmp(actual, expected, sizeof(actual)));
    }
    {
        unsigned char actual[32], expected[32];
        memset(actual, 0xa5, sizeof(actual));
        memset(expected, 0xa5, sizeof(expected));
        assert(p11_journal_header_init(actual, NULL) == -1);
        assert(!memcmp(actual, expected, sizeof(actual)));
        assert(p11_journal_header_init(NULL, &cases[0].spec) == -1);
        assert(journal_header_write(NULL, 224, 1, 0, 7, 3) == -1);
    }
}
/* A poison-filled 72-byte output must match independent retained facts for
 * every reason/phase. In particular, the expected body is not copied from
 * BEGIN or from the producer's intermediate framing structure. */
int main(void)
{
    const struct rlimit no_core = {0, 0};
    unsigned cells = 0;
    assert(!setrlimit(RLIMIT_CORE, &no_core));
    roots_header_poison_controls();
    for (u32 layout = 1; layout <= 2; layout++) {
        for (u32 object = 0; object <= 1; object++) {
            for (u32 reason = 0; reason <= 11; reason++) {
                unsigned char expected[72] = {};
                struct journal_settle_words out;
                struct journal_start_value identity;
                unsigned char retained[288];
                struct owner_start_key key;
                u32 actual_reason = reason ? reason : 9;
                roots_setup(object ? 21 : 17, 1, layout, object, 0);
                if (layout == 2) {
                    u64 session = 0x80000001ULL;
                    memcpy(roots_row(0) + 8, &session, 8);
                }
                roots_begin(&roots_context);
                assert(ring_submits == 1 && !producer_gaps);
                memcpy(retained, roots_row(0), sizeof(retained));
                identity = *(struct journal_start_value *)lookup(&JOURNAL_START, &producer_terminal_key);
                key = producer_terminal_key;
                if (reason == 11) {
                    struct journal_return_words returned;
                    roots_returning(&returned);
                    actual_reason = 0;
                    expected[64] = JOURNAL_SETTLE_SILENT;
                } else if (reason <= 9) {
                    expected[0] = 1;
                    expected[2] = 64;
                    expected[4] = 3;
                    memcpy(expected + 8, &identity.thread, 8);
                    memcpy(expected + 16, &identity.sequence, 8);
                    memcpy(expected + 24, &key.pid_tgid, 8);
                    memcpy(expected + 32, retained + 272, 16);
                    memcpy(expected + 48, &key.slot, 4);
                    memcpy(expected + 52, &actual_reason, 4);
                    memcpy(expected + 56, retained, 8);
                    expected[64] = JOURNAL_SETTLE_ABANDON;
                }
                memset(&out, 0xa5, sizeof(out));
                p11_journal_settle_prepare(&key, reason == 11 ? 0 : reason, &out);
                assert(!memcmp(&out, expected, sizeof(out)));
                assert(!lookup(&JOURNAL_START, &key));
                assert(lookup(&START, &key) && owners[0].flags);
                assert(ring_submits == 1 && !ring_discards);
                assert(producer_gaps == (reason == 0 || reason == 10));
                cells++;
            }
            roots_setup(object ? 21 : 17, 1, layout, object, 0);
            if (layout == 2) {
                u64 session = 0x80000001ULL;
                memcpy(roots_row(0) + 8, &session, 8);
            }
            roots_begin(&roots_context);
            {
                struct journal_settle_words out;
                struct journal_start_value before = *(struct journal_start_value *)lookup(&JOURNAL_START, &producer_terminal_key);
                memset(&out, 0xa5, sizeof(out));
                fail_journal_delete = 1;
                p11_journal_settle_prepare(&producer_terminal_key, 6, &out);
                assert(out.state == JOURNAL_SETTLE_BLOCKED && !out.pad);
                assert(!memcmp(&before, lookup(&JOURNAL_START, &producer_terminal_key), sizeof(before)));
                assert(lookup(&START, &producer_terminal_key) && owners[0].flags && ctl.outstanding == 1);
                assert(ring_submits == 1 && !ring_discards && producer_gaps == 1);
                fail_journal_delete = 0;
                assert(!roots_remove(6));
                assert(ring_submits == 2 && !lookup(&START, &producer_terminal_key) && !ctl.outstanding);
                assert(!failures);
            }
            cells++;
        }
    }
    assert(cells == 52);
    puts("52 native prepare and 23 header poison/refusal controls passed");
    return failures != 0;
}
#endif
