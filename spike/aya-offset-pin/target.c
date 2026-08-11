/* Built -no-pie so .text p_vaddr (0x40xxxx) != p_offset — the disagreement
 * case Phase 0 could not produce (SoftHSM2 has p_offset == p_vaddr). */
__attribute__((noinline)) void probe_me(void) { __asm__ volatile(""); }

int main(void) {
    for (int i = 0; i < 7; i++) probe_me();
    return 0;
}
