/* SPDX-License-Identifier: GPL-2.0-only */
/* Compile-only root consuming the real identity core; no copied allocator. */
#include "../../crates/ebpf/native/image_identity.c"

SEC("uprobe") int image_identity_core_canary(void *ctx)
{
    struct image_identity image = {};
    (void)ctx;
    return p11_link_current_identity(&image);
}
