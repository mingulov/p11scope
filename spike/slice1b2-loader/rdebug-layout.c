#include <link.h>
#include <stddef.h>
#include <stdio.h>

_Static_assert(offsetof(struct r_debug, r_state) == 24);

int main(void) {
    printf("RDEBUG_R_STATE_OFFSET=%zu sizeof_r_debug=%zu\n",
           offsetof(struct r_debug, r_state), sizeof(struct r_debug));
}
