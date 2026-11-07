/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Opus B4 static-sleeper fallback: raw-syscall sleeper, no libc.
 *
 * Built with `gcc -static -nostdlib` for hosts without busybox (CI
 * runners): argv[1] seconds (default 60), `_start` entry, `nanosleep`
 * resumed across EINTR, then `exit`. Maps no shared objects, so the
 * process is trivially ungrouped.
 */
typedef unsigned long u64;

static long sys3(long n, u64 a, u64 b, u64 c)
{
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}

struct sleep_ts {
    long tv_sec;
    long tv_nsec;
};

void _start(void)
{
    u64 *sp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));
    long secs = 60;
    if (sp[0] >= 2) {
        const char *p = (const char *)sp[2];
        long v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (*p - '0');
            p++;
        }
        if (v > 0) {
            secs = v;
        }
    }
    for (;;) {
        struct sleep_ts req;
        struct sleep_ts rem;
        req.tv_sec = secs;
        req.tv_nsec = 0;
        /* __NR_nanosleep = 35; EINTR resumes the remainder. */
        if (sys3(35, (u64)&req, (u64)&rem, 0) == 0) {
            break;
        }
        secs = rem.tv_sec > 0 ? rem.tv_sec : 1;
    }
    sys3(60 /* __NR_exit */, 0, 0, 0);
    __builtin_unreachable();
}
