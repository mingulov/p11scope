/* SPDX-License-Identifier: GPL-3.0-or-later */
#define P11SCOPE_IMAGE_QUERY_HOST_TEST
#include "../../../crates/ebpf/native/image_identity_query.c"
static u64 fixture_pid_tgid(void) { return 400ULL << 32; }
void selected_fixture_exec_release(void) { p11_image_exec_release(0); }
void selected_fixture_query_setup(void *lookup, void *update, void *clock)
{
    image_pid_tgid = fixture_pid_tgid;
    image_lookup = lookup;
    image_update = update;
    image_ktime = clock;
}
