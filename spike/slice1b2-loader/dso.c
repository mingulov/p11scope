#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *fixture_relocated_puts = (void *)puts;

void fixture_ctor_marker(void) {
    void *expected = (void *)puts;
    if (fixture_relocated_puts == NULL || fixture_relocated_puts != expected) {
        printf("DSO_RELOCATION_ASSERT_FAIL pid=%ld actual=%p expected=%p\n",
               (long)getpid(), fixture_relocated_puts, expected);
        fflush(stdout);
        _Exit(121);
    }
    printf("DSO_CONSTRUCTOR pid=%ld relocated_puts=%p expected_puts=%p\n",
           (long)getpid(), fixture_relocated_puts, expected);
    fflush(stdout);
}

__attribute__((constructor)) static void fixture_ctor(void) {
    fixture_ctor_marker();
}
