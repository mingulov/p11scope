#include <stdio.h>
extern void *fixture_relocated_puts;
int main(void) { puts("LAUNCHER_MAIN"); return fixture_relocated_puts == (void *)puts ? 0 : 121; }
