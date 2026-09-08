#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size) {
    (void)fd;
    if (strcmp(name, "security.capability") != 0 || size == 0) return -1;
    ((unsigned char *)value)[0] = 1;
    return 1;
}
