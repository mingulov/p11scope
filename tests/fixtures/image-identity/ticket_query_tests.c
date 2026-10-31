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
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef IMAGE_HOST_CAS_HOOK
extern int image_cas_fail_all;
#endif

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

/* A-bank task holds its identity while B reissues the local ticket:
 * identities stay distinct, re-queries stay stable, the local ticket
 * and the watermark keep their contracts. */
static void identity_distinct(void)
{
    struct image_identity a_now, a_later, b_now, b_later;
    u64 ticket = 0, watermark = 0;
    u64 n;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_identity(&leaders[1], &a_now) == COOKIE_STATUS_OK);
    assert(a_now.task_cookie == 1);
    puts("ASSERT identity_a_legacy_cookie");
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    present_b[2] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(p11_link_task_identity(&leaders[2], &b_now) == COOKIE_STATUS_OK);
    assert(b_now.task_cookie != a_now.task_cookie);
    puts("ASSERT identity_b_disjoint");
    assert(p11_link_task_identity(&leaders[1], &a_later) == COOKIE_STATUS_OK);
    assert(a_later.task_cookie == a_now.task_cookie);
    puts("ASSERT identity_a_survives_cut");
    assert(p11_link_task_identity(&leaders[2], &b_later) == COOKIE_STATUS_OK);
    assert(b_later.task_cookie == b_now.task_cookie);
    puts("ASSERT identity_b_requery_stable");
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    puts("ASSERT identity_ticket_stays_local");
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == IMAGE_IDENTITY_TICKET_LIMIT + 1);
    puts("ASSERT identity_watermark_monotonic");
}

/* Miniature consumer keyed by the full qualified cookie: one bank's
 * exec/return cannot touch the other's rows. This pins the allocator
 * seam (disjoint keys); the production query/continuation/
 * invalidation honoring is dispatched separately. */
#define ISO_ROWS 8
static u64 iso_cookie[ISO_ROWS];
static u64 iso_exec[ISO_ROWS];

static void iso_reset(void)
{
    int i;
    for (i = 0; i < ISO_ROWS; i++) {
        iso_cookie[i] = 0;
        iso_exec[i] = 0;
    }
}

static void iso_seed(u64 cookie, u64 exec)
{
    int i;
    for (i = 0; i < ISO_ROWS; i++) {
        if (iso_cookie[i] == cookie) {
            iso_exec[i] = exec;
            return;
        }
    }
    for (i = 0; i < ISO_ROWS; i++) {
        if (!iso_cookie[i]) {
            iso_cookie[i] = cookie;
            iso_exec[i] = exec;
            return;
        }
    }
    assert(!"miniature consumer overflowed");
}

static int iso_live(u64 cookie)
{
    int i;
    if (!cookie)
        return 0;
    for (i = 0; i < ISO_ROWS; i++) {
        if (iso_cookie[i] == cookie)
            return 1;
    }
    return 0;
}

static void iso_invalidate(u64 cookie)
{
    int i;
    for (i = 0; i < ISO_ROWS; i++) {
        if (iso_cookie[i] == cookie) {
            iso_cookie[i] = 0;
            iso_exec[i] = 0;
        }
    }
}

static int iso_match(u64 stored_cookie, u64 stored_exec, u64 fresh_cookie, u64 fresh_exec)
{
    return stored_cookie == fresh_cookie && stored_exec == fresh_exec;
}

/* Full bank lifecycle: fill both banks, refuse the stale cut, fold
 * exactly once on the Session claim, re-prepare under the loader's
 * fresh incarnation with fresh maps, cut back and reissue without
 * ever repeating a cookie. The fixture plays the loader role (delete
 * cells, publish incarnation, re-authorize) after observing the
 * kernel fold mark. */
static void bank_fold_lifecycle(void)
{
    struct image_identity first, adult;
    u64 ticket = 0, watermark = 0;
    u64 n;
    int i;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    /* Drop the churn slot's last A cell so the B fill cannot take the
     * retained path (the bank-cut twin does the same). */
    present[0] = 0;
    for (n = 0; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present_b[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    present_b[0] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(select_stub.refusals == 1);
    puts("ASSERT stale_cut_refuses_until_folded");
    select_stub.prepared[0] = 0;
    present_b[0] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(select_stub.folded[0] == 1);
    assert(select_stub.folds == 1);
    assert(select_stub.folded_issued == IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT fold_claim_retires_once");
    present_b[0] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(select_stub.folds == 1);
    assert(select_stub.folded_issued == IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT fold_never_repeats");
    for (i = 0; i < TASK_COUNT; i++) {
        present[i] = 0;
        stored[i] = 0;
    }
    select_stub.incarnation[0] = 1;
    select_stub.prepared[0] = 1;
    present_b[0] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(select_stub.bank == 0);
    assert(select_stub.folded[0] == 0);
    assert(ctl.next_ticket == 1);
    assert(select_stub.incarnation[0] == 1);
    assert(select_stub.cuts == 2);
    assert(select_stub.refusals == 3);
    puts("ASSERT reprepare_cuts_back_fresh");
    assert(p11_link_task_identity(&leaders[0], &first) == COOKIE_STATUS_OK);
    assert(first.task_cookie == image_identity_qualify(1, 0, 1));
    assert(first.task_cookie > IMAGE_IDENTITY_TICKET_LIMIT);
    assert(p11_link_task_identity(&leaders[1], &adult) == COOKIE_STATUS_OK);
    assert(adult.task_cookie == image_identity_qualify(2, 0, 1));
    assert(!iso_match(1, 0, first.task_cookie, first.exec_id));
    assert(!iso_match(2, 0, adult.task_cookie, adult.exec_id));
    puts("ASSERT reissue_never_repeats_cookie");
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == 2 * IMAGE_IDENTITY_TICKET_LIMIT + 2);
    puts("ASSERT watermark_monotonic_across_incarnations");
}

struct race_arg {
    int id;
    u32 status;
    u64 ticket;
    pthread_barrier_t *barrier;
};

static void *race_ticket(void *arg_raw)
{
    struct race_arg *arg = arg_raw;
    u64 ticket = 0;
    u32 status;
    (void)pthread_barrier_wait(arg->barrier);
    present[arg->id] = 0;
    present_b[arg->id] = 0;
    status = p11_link_task_ticket(&leaders[arg->id], &ticket);
    arg->status = status;
    arg->ticket = ticket;
    return 0;
}

/* Eight threads race the fold claim and then the re-prepare: the fold
 * applies once, the re-prepare applies once, and the reissued
 * tickets are distinct and disjoint from every legacy cookie. */
static void bank_reprepare_race(void)
{
    pthread_barrier_t barrier;
    pthread_t threads[TASK_COUNT];
    struct race_arg args[TASK_COUNT];
    struct image_identity got;
    u64 seen = 0;
    int i;

    reset();
    select_stub.prepared[1] = 1;
    for (i = 0; i < TASK_COUNT; i++) {
        present[i] = 0;
        stored[i] = 0;
    }
    ctl.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT;
    ctl_b.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT;
    select_stub.bank = 1;
    select_stub.cuts = 1;
    select_stub.prepared[0] = 0;
    assert(pthread_barrier_init(&barrier, 0, TASK_COUNT) == 0);
    for (i = 0; i < TASK_COUNT; i++) {
        args[i].id = i;
        args[i].status = 0;
        args[i].ticket = 0;
        args[i].barrier = &barrier;
        assert(pthread_create(&threads[i], 0, race_ticket, &args[i]) == 0);
    }
    for (i = 0; i < TASK_COUNT; i++)
        assert(pthread_join(threads[i], 0) == 0);
    assert(pthread_barrier_destroy(&barrier) == 0);
    for (i = 0; i < TASK_COUNT; i++)
        assert(args[i].status == COOKIE_STATUS_QUOTA);
    assert(select_stub.folded[0] == 1);
    assert(select_stub.folds == 1);
    assert(select_stub.folded_issued == IMAGE_IDENTITY_TICKET_LIMIT);
    assert(select_stub.refusals == TASK_COUNT);
    assert(ctl_b.unavailable == TASK_COUNT);
    assert(select_stub.update_losses == 0);
    puts("ASSERT concurrent_fold_once");
    for (i = 0; i < TASK_COUNT; i++) {
        present[i] = 0;
        stored[i] = 0;
    }
    select_stub.incarnation[0] = 1;
    select_stub.prepared[0] = 1;
    assert(pthread_barrier_init(&barrier, 0, TASK_COUNT) == 0);
    for (i = 0; i < TASK_COUNT; i++) {
        args[i].id = i;
        args[i].status = 0;
        args[i].ticket = 0;
        args[i].barrier = &barrier;
        assert(pthread_create(&threads[i], 0, race_ticket, &args[i]) == 0);
    }
    for (i = 0; i < TASK_COUNT; i++)
        assert(pthread_join(threads[i], 0) == 0);
    assert(pthread_barrier_destroy(&barrier) == 0);
    for (i = 0; i < TASK_COUNT; i++) {
        assert(args[i].status == COOKIE_STATUS_OK);
        assert(args[i].ticket >= 1 && args[i].ticket <= TASK_COUNT);
        assert(!(seen & (1ULL << args[i].ticket)));
        seen |= 1ULL << args[i].ticket;
    }
    assert(select_stub.bank == 0);
    assert(select_stub.folded[0] == 0);
    assert(select_stub.cuts == 2);
    assert(ctl.next_ticket == TASK_COUNT);
    puts("ASSERT concurrent_reprepare_once");
    for (i = 0; i < TASK_COUNT; i++) {
        assert(p11_link_task_identity(&leaders[i], &got) == COOKIE_STATUS_OK);
        assert(got.task_cookie == image_identity_qualify(args[i].ticket, 0, 1));
        assert(got.task_cookie > IMAGE_IDENTITY_TICKET_LIMIT);
    }
    puts("ASSERT concurrent_reissue_disjoint");
}

/* Exec/return isolation at the seam: each bank's exec invalidates only
 * its own rows, and returns join only identical identities. */
static void exec_return_isolation(void)
{
    struct image_identity a, b, a2;
    u64 ticket = 0;
    u64 n;

    reset();
    select_stub.prepared[1] = 1;
    iso_reset();
    assert(p11_link_task_identity(&leaders[1], &a) == COOKIE_STATUS_OK);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    }
    present_b[2] = 0;
    assert(p11_link_task_identity(&leaders[2], &b) == COOKIE_STATUS_OK);
    assert(a.task_cookie != b.task_cookie);
    iso_seed(a.task_cookie, a.exec_id);
    iso_seed(b.task_cookie, b.exec_id);
    assert(iso_live(a.task_cookie) && iso_live(b.task_cookie));
    iso_invalidate(a.task_cookie);
    assert(!iso_live(a.task_cookie) && iso_live(b.task_cookie));
    puts("ASSERT exec_invalidates_only_own_bank");
    iso_seed(a.task_cookie, a.exec_id);
    iso_invalidate(b.task_cookie);
    assert(iso_live(a.task_cookie) && !iso_live(b.task_cookie));
    puts("ASSERT exec_isolation_symmetric");
    assert(p11_link_task_identity(&leaders[1], &a2) == COOKIE_STATUS_OK);
    assert(iso_match(a.task_cookie, a.exec_id, a2.task_cookie, a2.exec_id));
    assert(!iso_match(a.task_cookie, a.exec_id, b.task_cookie, b.exec_id));
    assert(!iso_match(b.task_cookie, b.exec_id, a.task_cookie, a.exec_id));
    puts("ASSERT return_mismatches_across_banks");
}

/* Incarnation guard: the top of the 48-bit incarnation range still
 * issues; one past it refuses instead of wrapping the qualifier into
 * an aliasing cookie. */
static void incarnation_guard(void)
{
    struct image_identity got;
    u64 ticket = 0;

    reset();
    select_stub.prepared[1] = 1;
    select_stub.incarnation[0] = (1ULL << 48) - 1;
    present[0] = 0;
    assert(p11_link_task_identity(&leaders[0], &got) == COOKIE_STATUS_OK);
    assert(got.task_cookie == image_identity_qualify(1, 0, (1ULL << 48) - 1));
    puts("ASSERT incarnation_top_issues");
    reset();
    select_stub.prepared[1] = 1;
    select_stub.incarnation[0] = 1ULL << 48;
    present[1] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    assert(ctl.unavailable == 1);
    puts("ASSERT incarnation_overflow_refuses");
}

/* Empty slots never fold: an unprepared bank with no issuance is
 * fresh, not a fold claim, so admissions leave the fold marks alone.
 * (Regression guard: passes pre-implementation; the mutation run
 * proves it detects unconditional folding.) */
static void fold_skips_empty(void)
{
    u64 ticket = 0;

    reset();
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(select_stub.folds == 0);
    assert(select_stub.folded[0] == 0 && select_stub.folded[1] == 0);
    assert(select_stub.folded_issued == 0);
    puts("ASSERT fold_skips_empty");
}

static int stub_leader = 0;

static struct task_struct *stub_current_task(void)
{
    return &leaders[stub_leader];
}

/* EXEC binding stays local: the current-task cookie returns the
 * per-bank ticket on both banks, never the qualified identity.
 * (Regression guard: passes pre-implementation; the mutation run
 * proves it detects a qualifier leak into the binding.) */
static void binding_stays_local(void)
{
    u64 ticket = 0;
    u64 n;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    }
    present_b[2] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    bpf_get_current_task_btf = stub_current_task;
    stub_leader = 2;
    assert(p11_link_current_cookie() == 1);
    puts("ASSERT binding_b_stays_local");
    stub_leader = 1;
    assert(p11_link_current_cookie() == 1);
    puts("ASSERT binding_a_stays_local");
}

/* A healthy B admission folds the claimed bank: fold help is not
 * quota-gated. The pending-fold watermark excludes the retired bank
 * (its count already lives in folded_issued), the retired epoch still
 * serves its true identities, and the later re-prepare completes
 * without cutting while the current bank still has room. */
static void fold_pending_excludes(void)
{
    struct image_identity got;
    u64 ticket = 0, watermark = 0;
    u64 n;
    int i;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
        assert(ticket == n + 1);
    }
    present[0] = 0;
    present_b[2] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    select_stub.prepared[0] = 0;
    present_b[3] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[3], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 2);
    assert(select_stub.folded[0] == 1);
    assert(select_stub.folds == 1);
    assert(select_stub.folded_issued == IMAGE_IDENTITY_TICKET_LIMIT);
    puts("ASSERT fold_runs_on_healthy_admission");
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == IMAGE_IDENTITY_TICKET_LIMIT + 2);
    puts("ASSERT pending_fold_excluded_from_watermark");
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(p11_link_task_identity(&leaders[1], &got) == COOKIE_STATUS_OK);
    assert(got.task_cookie == 1);
    puts("ASSERT retired_epoch_still_serves");
    for (i = 0; i < TASK_COUNT; i++) {
        present[i] = 0;
        stored[i] = 0;
    }
    select_stub.incarnation[0] = 1;
    select_stub.prepared[0] = 1;
    present_b[4] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[4], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 3);
    assert(select_stub.bank == 1);
    assert(select_stub.folded[0] == 0);
    assert(ctl.next_ticket == 0);
    puts("ASSERT reprepare_without_cut_stays");
}

/* The incarnation guard refuses before spending: no ticket burns, the
 * refusal charges the corrupt bank once. */
static void guard_spends_nothing(void)
{
    u64 ticket = 99;

    reset();
    select_stub.prepared[1] = 1;
    select_stub.incarnation[0] = 1ULL << 48;
    present[1] = 0;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    assert(ctl.next_ticket == 0);
    assert(ctl.unavailable == 1);
    puts("ASSERT guard_spends_nothing");
}

/* A corrupt retained cell charges the bank that owns the corruption,
 * not the current bank. */
static void retained_zero_charges_source(void)
{
    u64 ticket = 0;
    u64 n;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    }
    present[0] = 0;
    present_b[2] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    assert(select_stub.bank == 1);
    present[0] = 1;
    stored[0] = 0;
    present_b[0] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_ZERO_CELL);
    assert(ticket == 0);
    assert(ctl.unavailable == 1);
    assert(ctl_b.unavailable == 0);
    puts("ASSERT retained_zero_charges_source");
}

/* A retained re-query validates the source domain: a corrupt source
 * bank refuses instead of serving from it. */
static void retained_validates_source(void)
{
    u64 ticket = 0;
    u64 n;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    }
    present[0] = 0;
    present_b[2] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    ctl.limit = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    assert(ctl.unavailable == 1);
    puts("ASSERT retained_validates_source");
}

/* A prepared cut target with an overflowed epoch is not a cut target:
 * the quota refuses without cutting into the corrupt epoch. */
static void cut_refuses_corrupt_target(void)
{
    u64 ticket = 0;
    u64 n;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    for (n = 1; n < IMAGE_IDENTITY_TICKET_LIMIT; n++) {
        present[0] = 0;
        ticket = 0;
        assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    }
    select_stub.incarnation[1] = 1ULL << 48;
    present[0] = 0;
    present_b[0] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_QUOTA);
    assert(ticket == 0);
    assert(select_stub.bank == 0);
    assert(select_stub.cuts == 0);
    assert(select_stub.refusals == 1);
    assert(ctl.unavailable == 1);
    puts("ASSERT cut_refuses_corrupt_target");
}

/* Fold help is not gated on the current bank's health: with the
 * current bank corrupt, the admission still retires the claimed bank
 * before refusing. */
static void fold_despite_corrupt_current(void)
{
    u64 ticket = 99;

    reset();
    select_stub.prepared[1] = 1;
    select_stub.bank = 1;
    ctl.next_ticket = 7;
    ctl_b.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT;
    select_stub.prepared[0] = 0;
    ctl_b.limit = 0;
    present[0] = 0;
    present_b[0] = 0;
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    assert(select_stub.folded[0] == 1);
    assert(select_stub.folds == 1);
    assert(select_stub.folded_issued == 7);
    assert(ctl_b.unavailable == 1);
    puts("ASSERT fold_despite_corrupt_current");
}

/* The incarnation guard covers re-queries too: a stored cell from
 * an overflowed epoch refuses instead of serving an aliasing cookie. */
static void hit_overflow_refuses(void)
{
    struct image_identity got;
    u64 ticket = 0;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    select_stub.incarnation[0] = 1ULL << 48;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    assert(ctl.unavailable == 1);
    assert(p11_link_task_identity(&leaders[1], &got) == COOKIE_STATUS_BAD_CONFIG);
    assert(got.task_cookie == 0);
    puts("ASSERT hit_overflow_refuses");
}

/* Domain before row: a zero cell in an overflowed epoch reports the
 * corrupt epoch, not the corrupt cell. */
static void guard_before_zero_cell(void)
{
    u64 ticket = 99;

    reset();
    select_stub.prepared[1] = 1;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    select_stub.incarnation[0] = 1ULL << 48;
    stored[1] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ticket == 0);
    puts("ASSERT guard_before_zero_cell");
}

#ifdef IMAGE_HOST_CAS_HOOK
/* Exhaustion twin: with every identity saturating-counter CAS forced
 * to fail, settled updates still land through the fallback and every
 * unsettled update reports through update_losses. */
static void identity_cas_exhaustion(void)
{
    u64 ticket = 0, watermark = 0;

    reset();
    assert(p11_link_task_ticket(&leaders[0], &ticket) == COOKIE_STATUS_OK);
    assert(ticket == 1);
    image_cas_fail_all = 1;
    ctl.limit = 0;
    present[1] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[1], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ctl.unavailable == 1);
    assert(select_stub.update_losses == 0);
    puts("ASSERT identity_fallback_settles");
    ctl.unavailable = ~0ULL - 1;
    present[2] = 0;
    ticket = 0;
    assert(p11_link_task_ticket(&leaders[2], &ticket) == COOKIE_STATUS_BAD_CONFIG);
    assert(ctl.unavailable == ~0ULL - 1);
    assert(select_stub.update_losses == 1);
    puts("ASSERT identity_skip_reports");
    ctl.limit = IMAGE_IDENTITY_TICKET_LIMIT;
    ctl.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT;
    ctl.unavailable = 0;
    present[3] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[3], &ticket) == COOKIE_STATUS_QUOTA);
    assert(ctl.unavailable == 1);
    assert(select_stub.refusals == 1);
    assert(select_stub.update_losses == 1);
    puts("ASSERT identity_bank_refusal_settles");
    image_cas_fail_all = 0;
    ctl_b.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT;
    select_stub.bank = 1;
    select_stub.prepared[0] = 0;
    select_stub.folded_issued = ~0ULL - 1;
    present[4] = 0;
    present_b[4] = 0;
    ticket = 99;
    assert(p11_link_task_ticket(&leaders[4], &ticket) == COOKIE_STATUS_QUOTA);
    assert(select_stub.folded[0] == 1);
    assert(select_stub.folds == 1);
    assert(select_stub.folded_issued == ~0ULL);
    puts("ASSERT identity_folded_saturates");
    assert(p11_image_identity_issued(&watermark) == COOKIE_STATUS_OK);
    assert(watermark == ~0ULL);
    puts("ASSERT identity_watermark_saturates");
}
#endif

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
    } else if (!strcmp(argv[1], "identity-distinct")) {
        identity_distinct();
    } else if (!strcmp(argv[1], "bank-fold-lifecycle")) {
        bank_fold_lifecycle();
    } else if (!strcmp(argv[1], "bank-reprepare-race")) {
        bank_reprepare_race();
    } else if (!strcmp(argv[1], "exec-return-isolation")) {
        exec_return_isolation();
    } else if (!strcmp(argv[1], "incarnation-guard")) {
        incarnation_guard();
    } else if (!strcmp(argv[1], "fold-skips-empty")) {
        fold_skips_empty();
    } else if (!strcmp(argv[1], "binding-stays-local")) {
        binding_stays_local();
    } else if (!strcmp(argv[1], "fold-pending-excludes")) {
        fold_pending_excludes();
    } else if (!strcmp(argv[1], "guard-spends-nothing")) {
        guard_spends_nothing();
    } else if (!strcmp(argv[1], "retained-zero-charges-source")) {
        retained_zero_charges_source();
    } else if (!strcmp(argv[1], "retained-validates-source")) {
        retained_validates_source();
    } else if (!strcmp(argv[1], "cut-refuses-corrupt-target")) {
        cut_refuses_corrupt_target();
    } else if (!strcmp(argv[1], "fold-despite-corrupt-current")) {
        fold_despite_corrupt_current();
    } else if (!strcmp(argv[1], "hit-overflow-refuses")) {
        hit_overflow_refuses();
    } else if (!strcmp(argv[1], "guard-before-zero-cell")) {
        guard_before_zero_cell();
#ifdef IMAGE_HOST_CAS_HOOK
    } else if (!strcmp(argv[1], "identity-cas-exhaustion")) {
        identity_cas_exhaustion();
#endif
    } else {
        return 2;
    }
    printf("SCENARIO %s PASS\n", argv[1]);
    return 0;
}
