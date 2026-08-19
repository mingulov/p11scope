// Loader artifact fixture (Task 7): a minimal dynamic executable whose own
// startup drives the PT_INTERP loader through _dl_debug_state (RT_ADD then
// RT_CONSISTENT), plus a bounded single-hit hook for the §8.1 no-cookie
// negative. It blocks on stdin until the runner closes the pipe so /proc facts
// stay observable, then exits.
#include <unistd.h>

__attribute__((noinline)) void spike_loader_negative_hook(void)
{
    __asm__ volatile("");
}

int main(int argc, char **argv)
{
    if (argc > 1 && __builtin_expect(argv[1][0] == '-', 0)) {
        spike_loader_negative_hook();
        return 0;
    }
    spike_loader_negative_hook();
    char byte;
    while (read(0, &byte, 1) == 1) {
    }
    return 0;
}
