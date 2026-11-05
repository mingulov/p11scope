/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../../../crates/ebpf/native/image_identity.c"
void selected_fixture_identity_setup(void *lookup, void *storage, void *current)
{
    bpf_map_lookup_elem = lookup;
    bpf_task_storage_get = storage;
    bpf_get_current_task_btf = current;
}
