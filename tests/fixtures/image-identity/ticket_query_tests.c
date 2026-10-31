/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "image_identity.h"
/* Weak declarations make the pre-implementation test fail at the actual
 * missing helper assertion, without a link-error masquerading as runtime
 * RED (same trick as this fixture's helper_tests.c). */
extern u32 p11_link_task_ticket(struct task_struct *task, u64 *ticket_out)
    __attribute__((weak));
extern u32 p11_image_identity_issued(u64 *watermark_out) __attribute__((weak));
extern u32 p11_image_bank_select(void) __attribute__((weak));
extern u32 p11_image_bank_cut(u64 target) __attribute__((weak));
/* Map presence is compile-enforced now: the stub routing below
 * references the bank maps, so an ifdefed-out bank fails the build. */
#include "image_identity.c"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Eight tasks with distinct leaders; storage keyed by leader identity. */
#define TASK_COUNT 8
static struct control ctl;
static u64 stored[TASK_COUNT];
static int present[TASK_COUNT];
static struct control ctl_b;
static u64 stored_b[TASK_COUNT];
static int present_b[TASK_COUNT];
static struct image_bank_select select_stub;
static int select_present = 1;
static int fail_create, control_present = 1;
static unsigned int storage_calls, create_calls;
static struct task_struct leaders[TASK_COUNT];
static struct task_struct workers[TASK_COUNT];

/* The exec-id test aliases one guarded task pointer onto slot 0. */
static struct task_struct *aliased;

static int task_index(const struct task_struct *task)
{
    int i;
    if (task == aliased)
        return 0;
    for (i = 0; i < TASK_COUNT; i++) {
        if (task == &leaders[i])
            return i;
    }
    return -1;
}

static void *lookup(void *map, const void *key)
{
    (void)key;
    if (map == &IMAGE_BANK_SELECT)
        return select_present ? &select_stub : 0;
    if (map == &COOKIE_CTL_B)
        return &ctl_b;
    if (map == &COOKIE_CTL)
        return control_present ? &ctl : 0;
    return 0;
}

static u64 *storage(void *map, struct task_struct *task, u64 *value, u64 flags)
{
    int index;
    u64 *cells;
    int *marks;
    index = task_index(task);
    assert(index >= 0);
    storage_calls++;
    if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE)
        create_calls++;
    if (map == &TASK_COOKIE_B) {
        cells = stored_b;
        marks = present_b;
    } else {
        cells = stored;
        marks = present;
    }
    if (marks[index])
        return &cells[index];
    if (!value || fail_create)
        return 0;
    cells[index] = *value;
    marks[index] = 1;
    return &cells[index];
}

static void reset(void)
{
    int i;
    ctl = (struct control){ .limit = IMAGE_IDENTITY_TICKET_LIMIT };
    ctl_b = (struct control){ .limit = IMAGE_IDENTITY_TICKET_LIMIT };
    select_stub = (struct image_bank_select){
        .bank = 0,
        .prepared = { 1, 0 },
        .cuts = 0,
        .refusals = 0,
    };
    select_present = 1;
    for (i = 0; i < TASK_COUNT; i++) {
        stored[i] = 0;
        present[i] = 0;
        stored_b[i] = 0;
        present_b[i] = 0;
        leaders[i].tgid = 100 + i;
        leaders[i].group_leader = &leaders[i];
        leaders[i].self_exec_id = 0;
        workers[i].tgid = 100 + i;
        workers[i].group_leader = &leaders[i];
        workers[i].self_exec_id = 0;
    }
    fail_create = 0;
    control_present = 1;
    aliased = 0;
    storage_calls = create_calls = 0;
}

/* Healthy twin: per-task ticket queries observe factual issuance, and the
 * watermark tracks every spent ticket including burns. */
static void ticket_query_healthy(void)
{
    u64 ticket = 0, watermark = 0;
    u64 seen[TASK_COUNT];
    int i;
    assert(&p11_link_task_ticket && "T-L2 needs the typed-task ticket query");
    assert(&p11_image_identity_issued && "T-L2 needs the issuance watermark");
    reset();
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == 0);
    /* A pure watermark read spends nothing and touches no task storage. */
    assert(storage_calls == 0 && create_calls == 0);
    for (i = 0; i < TASK_COUNT; i++) {
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[i], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == (u64)(i + 1));
        seen[i] = ticket;
    }
    /* Re-queries are stable: no new ticket is spent. */
    for (i = 0; i < TASK_COUNT; i++) {
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[i], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == (u64)(i + 1));
    }
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == TASK_COUNT);
    /* Issued tickets are strictly increasing: no number is ever reused. */
    for (i = 1; i < TASK_COUNT; i++)
        assert(seen[i] > seen[i - 1]);
    /* A burned ticket advances the watermark but never issues: the next
     * task observes the number after the burn, never the burned one. */
    reset();
    fail_create = 1;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_CREATE_FAILED);
    assert(ticket == 0);
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == 1);
    fail_create = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == watermark + 1 && ticket == 2);
    puts("ASSERT watermark_tracks_burns");
    puts("ASSERT burned_ticket_never_issues");
    puts("ASSERT tickets_strictly_increasing");
}

/* Failure twins: every malformed input refuses with its exact status and
 * spends nothing. */
static void ticket_query_failures(void)
{
    u64 ticket = 99, watermark = 99;
    u64 calls;
    reset();
    assert(p11_link_task_ticket(0, &ticket) == COOKIE_STATUS_BAD_TASK);
    assert(ticket == 0);
    assert(p11_link_task_ticket(&leaders[0], 0) == COOKIE_STATUS_BAD_TASK);
    assert(p11_image_identity_issued(0) == COOKIE_STATUS_BAD_TASK);
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == 0 && ctl.next_ticket == 0);
    puts("ASSERT null_inputs_bad_task");
    /* No control row: both queries refuse without touching storage. */
    control_present = 0;
    calls = storage_calls;
    ticket = watermark = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_NO_CONTROL);
    assert(ticket == 0);
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_NO_CONTROL);
    assert(watermark == 0 && ctl.next_ticket == 0);
    assert(storage_calls == calls);
    puts("ASSERT no_control_refuses_quiet");
    /* Bad configuration refuses; the read-only watermark never bumps the
     * unavailable counter (cookie issuance still does, once). */
    control_present = 1;
    ctl.limit = 0;
    ticket = watermark = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    assert(ctl.unavailable == 1);
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_BAD_CONFIG);
    assert(watermark == 0 && ctl.unavailable == 1);
    ctl.limit = IMAGE_IDENTITY_TICKET_LIMIT;
    ctl.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT + 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_BAD_CONFIG);
    puts("ASSERT bad_config_spends_nothing_readonly");
    /* Zero cell and quota: exact statuses, exact counters. */
    reset();
    present[2] = 1;
    stored[2] = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_ZERO_CELL);
    assert(ticket == 0 && ctl.next_ticket == 0);
    ctl.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[3], &ticket) == COOKIE_STATUS_QUOTA);
    assert(ticket == 0 && ctl.next_ticket == IMAGE_IDENTITY_TICKET_LIMIT);
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT zero_cell_and_quota_exact");
}

/* G17-shaped crossing: issuance reaches exactly 16,384, then refuses. */
static void ticket_crosses_16384(void)
{
    u64 ticket = 0, watermark = 0;
    u64 n;
    reset();
    /* Reuse one leader slot per issue by clearing presence: each issue
     * spends exactly one ticket from the shared control. */
    for (n = 0; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == IMAGE_IDENTITY_TICKET_LIMIT);
    present[0] = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT watermark_reaches_16384");
    puts("ASSERT next_attempt_quota");
}

/* The ticket query never reads self_exec_id: put that field on a
 * no-access page and issue through the same leader. */
static void ticket_ignores_exec_id(void)
{
    u64 ticket = 0;
    long page = sysconf(_SC_PAGESIZE);
    char *guard;
    assert(page > (long)sizeof(struct task_struct));
    reset();
    guard = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED);
    assert(mprotect(guard + page, (size_t)page, PROT_NONE) == 0);
    /* Alias the guarded task onto slot 0: the query must succeed without
     * reading self_exec_id, which sits on the no-access page. */
    aliased = (void *)(guard + page - offsetof(struct task_struct, self_exec_id));
    ticket = 0;
    assert(p11_link_task_ticket(aliased, &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(munmap(guard, (size_t)page * 2) == 0);
    puts("ASSERT ticket_query_ignores_exec_id");
}

/* G17-shaped cut: with B prepared, the 16,385th birth cuts to B
 * exactly once and lands there; B quota refuses honestly after both
 * banks fill, with saturating counted refusals. */
static void bank_cut_once(void)
{
    u64 ticket = 0, watermark = 0;
    u64 n;
    assert(&p11_image_bank_select && "bank promotion needs select");
    assert(&p11_image_bank_cut && "bank promotion needs cut");
    reset();
    /* The Session prepares B before A fills, as the contract requires. */
    select_stub.prepared[1] = 1;
    for (n = 0; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == IMAGE_IDENTITY_TICKET_LIMIT);
    present[0] = 0;
    present_b[0] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(select_stub.cuts == 1);
    assert(select_stub.bank == 1);
    puts("ASSERT cut_flips_to_b_once");
    assert(ctl.next_ticket == IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT a_watermark_frozen");
    assert(ctl_b.next_ticket == 1);
    puts("ASSERT b_issues_from_one");
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == IMAGE_IDENTITY_TICKET_LIMIT + 1);
    puts("ASSERT total_crosses_16384");
    /* A second cut is idempotent: no double count, admissions flow. */
    assert(p11_image_bank_cut(1) == 1);
    assert(select_stub.cuts == 1);
    puts("ASSERT second_cut_no_double_count");
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present_b[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == 2 * IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT total_reaches_32768");
    present_b[0] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(ticket == 0);
    assert(select_stub.cuts == 1);
    puts("ASSERT b_quota_honest");
    assert(select_stub.refusals == 1);
    puts("ASSERT bank_refusals_counted");
    select_stub.refusals = ~0ULL - 1;
    present_b[0] = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(select_stub.refusals == ~0ULL);
    present_b[0] = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(select_stub.refusals == ~0ULL);
    puts("ASSERT bank_refusals_saturate");
}

/* Retained routes: a pre-cut ticket still resolves from its bank after
 * the cut, new births land in B, and A storage is undisturbed. */
static void bank_query_routes(void)
{
    u64 ticket = 0;
    u64 n;
    assert(&p11_image_bank_select && "bank promotion needs select");
    assert(&p11_image_bank_cut && "bank promotion needs cut");
    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[1] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(select_stub.bank == 1 && select_stub.cuts == 1);
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(stored[0] == 1 && present[0]);
    puts("ASSERT pre_cut_ticket_retained");
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[3], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 2);
    assert(stored_b[3] == 2 && present_b[3]);
    puts("ASSERT post_cut_new_bank_b");
    assert(stored[0] == 1 && present[0]);
    assert(ctl.next_ticket == IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT a_storage_undisturbed");
}

/* Selection validation: unpublished, corrupt or missing SELECT refuses
 * new issues; cut validates its target and the prepared bit. */
static void bank_select_validation(void)
{
    u64 ticket = 99;
    u64 calls;
    assert(&p11_image_bank_select && "bank promotion needs select");
    assert(&p11_image_bank_cut && "bank promotion needs cut");
    reset();
    select_stub.bank = 0;
    select_stub.prepared[0] = 0;
    select_stub.prepared[1] = 0;
    assert(p11_image_bank_select() == IMAGE_BANK_NO_SLOT);
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    puts("ASSERT unpublished_select_refuses");
    select_stub.prepared[0] = 1;
    select_stub.bank = 7;
    assert(p11_image_bank_select() == IMAGE_BANK_NO_SLOT);
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    puts("ASSERT bad_bank_refuses");
    select_stub.bank = 0;
    select_present = 0;
    assert(p11_image_bank_select() == IMAGE_BANK_NO_SLOT);
    ticket = 99;
    calls = storage_calls;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    assert(storage_calls == calls);
    puts("ASSERT missing_select_refuses");
    /* Only the two present-word refusals count: a missing SELECT has no
     * cell, so like the gate's missing control it refuses uncounted. */
    assert(select_stub.refusals == 2);
    puts("ASSERT bad_select_counted");
    select_present = 1;
    assert(p11_image_bank_cut(7) == IMAGE_BANK_NO_SLOT);
    select_present = 0;
    assert(p11_image_bank_cut(1) == IMAGE_BANK_NO_SLOT);
    select_present = 1;
    select_stub.bank = 0;
    select_stub.prepared[0] = 1;
    select_stub.prepared[1] = 0;
    assert(p11_image_bank_cut(1) == IMAGE_BANK_NO_SLOT);
    assert(select_stub.cuts == 0);
    puts("ASSERT cut_validates_target");
    select_stub.prepared[1] = 1;
    assert(p11_image_bank_cut(1) == 1);
    assert(select_stub.bank == 1 && select_stub.cuts == 1);
    assert(p11_image_bank_cut(1) == 1);
    assert(select_stub.cuts == 1);
    puts("ASSERT cut_flips_once_ready");
}

int main(int argc, char **argv)
{
    bpf_map_lookup_elem = lookup;
    bpf_task_storage_get = storage;
    if (argc != 2)
        return 2;
    if (!strcmp(argv[1], "ticket-query-healthy")) {
        ticket_query_healthy();
    } else if (!strcmp(argv[1], "ticket-query-failures")) {
        ticket_query_failures();
    } else if (!strcmp(argv[1], "ticket-crosses-16384")) {
        ticket_crosses_16384();
    } else if (!strcmp(argv[1], "ticket-ignores-exec-id")) {
        ticket_ignores_exec_id();
    } else if (!strcmp(argv[1], "bank-cut-once")) {
        bank_cut_once();
    } else if (!strcmp(argv[1], "bank-query-routes")) {
        bank_query_routes();
    } else if (!strcmp(argv[1], "bank-select-validation")) {
        bank_select_validation();
    } else {
        return 2;
    }
    printf("SCENARIO %s PASS\n", argv[1]);
    return 0;
}
