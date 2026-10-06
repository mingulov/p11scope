/* SPDX-License-Identifier: GPL-3.0-or-later */
/* instance-continuity: owned Task 3 Stage A continuity workloads.
 *
 * Built with -DINSTANCE_PROVIDER -shared -fPIC this file is a tiny provider
 * whose C_GetSlotInfo returns CKR_SLOT_ID_INVALID (3) for every tag. Built
 * plainly it is the driver (link -ldl -lpthread):
 *
 *   instance-continuity cmd PROVIDER
 *       Single-byte commands on stdin, one reply line each on stdout:
 *       c  call C_GetSlotInfo(0x70000000 + gen) through the current handle
 *       C  call it through the dlmopen sibling, tag 0x71000000 + gen
 *       r  reload: dlclose then dlopen (gen += 1)        -> RELOAD gen old new
 *       d  dlmopen(LM_ID_NEWLM) a sibling copy           -> SIBLING base
 *       m  mmap+munmap an unrelated file                 -> UNRELATED
 *       p  mmap one page of the provider file and keep it -> PMAP
 *       P  munmap that page                              -> PUNMAP
 *       D  MADV_DONTNEED that page                        -> PDONTNEED
 *       F  MAP_FIXED anonymous memory over that page      -> PFIXED
 *       q  mmap two provider pages                        -> P2MAP
 *       s  mprotect the second one PROT_NONE (VMA split)  -> PSPLIT
 *       Q  munmap the pair                                -> P2UNMAP
 *       R  start a racing caller thread (tag 0x72000000 + gen) -> RACING
 *       S  stop it and print its per-generation ledger    -> RACED gen:n,...
 *       U  pure MREMAP_DONTUNMAP of that page (both stay) -> PUREMOVE
 *       V  vfork child unmaps that shared page             -> VUNMAP
 *       w  hold a persistent CLONE_VM sharer (pre-attach)  -> SHARER_HELD pid
 *       W  wake it to map+unmap one provider page          -> SHARER_WOKE
 *       z  hold a zombie-leader + CLONE_VM sharer scenario  -> ZOMBIE_HELD pid
 *       Z  wake its worker to map+unmap one provider page  -> ZOMBIE_WOKE
 *       h  another process punch-holes the provider file   -> PHOLE
 *       e  exec self (pipes survive; READY again)          -> (READY ...)
 *       E  a non-leader thread execs self                  -> (READY ...)
 *       f  fork a child that exits without exec            -> FORKED
 *       L  start a dlmopen/dlclose loop thread             -> LOOPING
 *       n  loop iterations so far (no stop)                -> LOOPCOUNT n
 *       l  stop it and print its iterations                -> LOOPED n
 *       H  two threads hammer tight calls (async)          -> HAMMERING/HAMMERED
 *       x  exit
 *       Reloads take a write lock that racing calls hold for reading, so a
 *       racing call never executes in an unmapped image; calls still race
 *       every stamp, scan and reload boundary.
 *   instance-continuity ovf P0 P1 ... P8
 *       Nine-file overflow workload: all nine files are loaded at startup
 *       (before any attach, so unwatched), then '0'-'8' reload file N and
 *       'c' calls C_GetSlotInfo through file 8's handle (tag 0x70000000).
 *       'x' exits. Replies: READY, REOPENED n, CALL rv.
 *   instance-continuity churn PROVIDER UNRELATED_FILE UNRELATED_SO SECONDS RATE
 *       SoftHSM2 long-lived key workload (C_Initialize, login as user 1234,
 *       one AES-256 session key, then tagged C_GetSlotInfo + C_Encrypt calls
 *       every millisecond) while one churn thread runs RATE unrelated mapping
 *       operations per second for SECONDS seconds (op mix: anonymous 256 KiB
 *       mmap/munmap, realloc through mremap, MAP_FIXED over anonymous memory,
 *       anonymous mprotect, unrelated file mmap/munmap, unrelated dlopen/
 *       dlclose, identical-flag mprotect of provider text).
 *
 * Every line is this process's own ledger; it never reads observer state.
 * The generation tag is the C_GetSlotInfo slot argument, which the observer
 * captures as the call's slot_id, so each observed call names the mapping
 * generation it ran in independently of any routing decision. */
#define _GNU_SOURCE
#ifdef INSTANCE_PROVIDER
typedef unsigned long CK_ULONG;
/* Some text before the endpoint so it does not sit at the segment start. */
__attribute__((noinline)) CK_ULONG instance_continuity_pad(CK_ULONG v)
{
    return v * 2654435761UL ^ (v >> 7);
}
CK_ULONG C_GetSlotInfo(CK_ULONG slot, void *info)
{
    (void)info;
    return instance_continuity_pad(slot) == 1 ? 0 : 3;
}
#else
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG (*slot_info_fn)(CK_ULONG, void *);

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* A CLONE_VM non-thread child (posix_spawn/vfork shape) that maps and
 * unmaps one provider page in the shared mm, then exits. */
static const char *sharer_provider;
static int sharer_child(void *unused)
{
    (void)unused;
    int fd = open(sharer_provider, O_RDONLY);
    if (fd < 0)
        return 1;
    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return 2;
    munmap(p, 4096);
    return 0;
}

/* A persistent CLONE_VM non-thread sharer, held across the observer's
 * attach: 'w' spawns it (it blocks on a pipe), 'W' wakes it to map and
 * unmap one provider page in the shared mm, then reaps it. CLONE_VM
 * shares memory, so file-scope state serves both processes; the fd table
 * is private (no CLONE_FILES), so the pipe ends stay valid in each. A
 * wake by EOF (the parent went away) exits quietly without mutating. */
static int held_sharer_pipe[2] = { -1, -1 };
static const char *held_sharer_provider;
static pid_t held_sharer;

static int held_sharer_child(void *unused)
{
    (void)unused;
    char gate;
    ssize_t n;
    /* The fd table is private (no CLONE_FILES): drop our own write end
     * first, so the parent's close (or death) lands as EOF instead of
     * blocking here forever behind our inherited copy. */
    close(held_sharer_pipe[1]);
    n = read(held_sharer_pipe[0], &gate, 1);
    if (n != 1)
        return 0;
    int fd = open(held_sharer_provider, O_RDONLY);
    if (fd < 0)
        return 1;
    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return 2;
    munmap(p, 4096);
    return 0;
}

/* A zombie-leader scenario (F3 soundness): 'z' forks a child whose main
 * thread spawns a worker thread plus a held CLONE_VM sharer and then
 * exits, leaving a zombie group leader; 'Z' wakes the worker to map and
 * unmap one provider page while the leader is still a zombie and the
 * external sharer holds the mm. The worker self-validates the window
 * (leader State Z, Threads 2, sharer alive) and exits nonzero when it is
 * not live, so a silent fixture miss fails loudly instead of passing
 * vacuously. Only the scenario child prints ZOMBIE_HELD; only the driver
 * prints ZOMBIE_WOKE. */
static int zombie_wake[2] = { -1, -1 };
static pid_t zombie_child;
static int zombie_hold[2] = { -1, -1 };
static const char *zombie_provider;
static pid_t zombie_sharer;

static int zombie_sharer_child(void *unused)
{
    (void)unused;
    char gate;
    /* Our own write end first (private fd table): the worker's close (or
     * the scenario's death) then lands as EOF. Either outcome releases us;
     * we only ever hold an mm reference, never mutate. */
    close(zombie_hold[1]);
    if (read(zombie_hold[0], &gate, 1) < 0)
        return 0;
    return 0;
}

/* Bounded reap of the scenario sharer, SIGKILL fallback: the fixture must
 * never hang its harness. Runs in the scenario child only. */
static void zombie_wait_sharer(void)
{
    int status = 0;
    int i;

    for (i = 0; i < 200; i++) {
        if (waitpid(zombie_sharer, &status, WNOHANG) == zombie_sharer)
            return;
        struct timespec pause = { 0, 10 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }
    kill(zombie_sharer, SIGKILL);
    waitpid(zombie_sharer, &status, 0);
}

/* True when the calling process is exactly {zombie leader, this worker}:
 * the group leader (tid == pid) is State Z and the group has 2 threads. */
static int zombie_window_live(void)
{
    char path[64];
    char status[4096];
    char threads[4096];
    int fd;
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/self/task/%d/status", (int)getpid());
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    status[n] = '\0';
    fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0)
        return 0;
    n = read(fd, threads, sizeof(threads) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    threads[n] = '\0';
    return strstr(status, "State:\tZ") != NULL && strstr(threads, "Threads:\t2") != NULL;
}

static void *zombie_worker(void *unused)
{
    (void)unused;
    char gate;
    int fd;
    void *p;
    ssize_t n = read(zombie_wake[0], &gate, 1);
    if (n != 1) {
        /* EOF: the driver went away ('x' path) — release the sharer and
         * leave without mutating. */
        close(zombie_hold[1]);
        zombie_wait_sharer();
        exit(0);
    }
    /* The leader may still be exiting when the wake lands: poll for the
     * zombie window (bounded), so the mutation below always runs inside
     * it — or the scenario fails loudly instead of testing nothing. */
    for (int i = 0; i < 50 && !zombie_window_live(); i++) {
        struct timespec pause = { 0, 100 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }
    if (!zombie_window_live() || kill(zombie_sharer, 0) != 0) {
        close(zombie_hold[1]);
        zombie_wait_sharer();
        exit(3);
    }
    fd = open(zombie_provider, O_RDONLY);
    if (fd < 0) {
        close(zombie_hold[1]);
        zombie_wait_sharer();
        exit(2);
    }
    p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        close(zombie_hold[1]);
        zombie_wait_sharer();
        exit(2);
    }
    munmap(p, 4096);
    close(zombie_hold[1]);
    zombie_wait_sharer();
    exit(0);
    return NULL;
}

/* The 'z' child: set up the worker plus the held sharer, print the Held
 * line, then exit the main thread so the leader stays a zombie while the
 * worker runs. Returns only on setup failure (after printing FAIL). */
static void zombie_scenario_child(void)
{
    static char stack[64 * 1024] __attribute__((aligned(16)));
    pthread_t worker;

    close(zombie_wake[1]);
    if (pipe2(zombie_hold, O_CLOEXEC) != 0) {
        printf("FAIL zombie hold pipe %s\n", strerror(errno));
        fflush(stdout);
        return;
    }
    if (pthread_create(&worker, NULL, zombie_worker, NULL) != 0) {
        printf("FAIL zombie worker %s\n", strerror(errno));
        fflush(stdout);
        return;
    }
    zombie_sharer = clone(zombie_sharer_child, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
    if (zombie_sharer < 0) {
        printf("FAIL zombie sharer %s\n", strerror(errno));
        fflush(stdout);
        return;
    }
    printf("ZOMBIE_HELD %d\n", (int)getpid());
    fflush(stdout);
    pthread_exit(NULL);
}

/* Graceful shutdown with a held zombie scenario: EOF wakes the worker,
 * which releases the sharer and leaves; then reap the scenario. Bounded
 * wait with a SIGKILL fallback. */
static void release_zombie_child(void)
{
    int status = 0;
    int i;

    if (!zombie_child)
        return;
    close(zombie_wake[1]);
    zombie_wake[1] = -1;
    for (i = 0; i < 200; i++) {
        if (waitpid(zombie_child, &status, WNOHANG) == zombie_child)
            break;
        struct timespec pause = { 0, 10 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }
    if (kill(zombie_child, 0) == 0) {
        kill(zombie_child, SIGKILL);
        waitpid(zombie_child, &status, 0);
    }
    zombie_child = 0;
}

/* Graceful shutdown with a held sharer: EOF wakes it (its own write end
 * is closed, so this close lands), then reap it. Bounded wait with a
 * SIGKILL fallback: the fixture must never hang its harness. */
static void release_held_sharer(void)
{
    int status = 0;
    int i;

    if (!held_sharer)
        return;
    close(held_sharer_pipe[1]);
    held_sharer_pipe[1] = -1;
    for (i = 0; i < 200; i++) {
        if (waitpid(held_sharer, &status, WNOHANG) == held_sharer)
            break;
        struct timespec pause = { 0, 10 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }
    if (kill(held_sharer, 0) == 0) {
        kill(held_sharer, SIGKILL);
        waitpid(held_sharer, &status, 0);
    }
    if (held_sharer_pipe[0] >= 0)
        close(held_sharer_pipe[0]);
    held_sharer_pipe[0] = -1;
    held_sharer = 0;
}

static uintptr_t base_of(void *handle)
{
    struct link_map *map = NULL;
    if (!handle || dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || !map)
        return 0;
    return (uintptr_t)map->l_addr;
}

static void die(const char *what)
{
    fprintf(stdout, "FAIL %s %s\n", what, dlerror() ? dlerror() : strerror(errno));
    fflush(stdout);
    exit(2);
}

#define RACE_GENS 4096
static pthread_rwlock_t image_lock = PTHREAD_RWLOCK_INITIALIZER;
static void *race_handle;
static atomic_uint race_gen;
static atomic_int race_stop;
static unsigned long race_counts[RACE_GENS];

/* The main handle's resolved endpoint, cached across calls: after a
 * punch-hole zeroes the file's header page, dlsym can no longer validate
 * the image, while a cached pointer still executes intact text. The cache
 * is keyed by handle, so reloads re-resolve. */
static void *cached_handle;
static slot_info_fn cached_call;

static slot_info_fn main_call(void *handle)
{
    if (handle != cached_handle) {
        cached_call = handle ? (slot_info_fn)dlsym(handle, "C_GetSlotInfo") : NULL;
        cached_handle = handle;
    }
    return cached_call;
}

/* dlmopen/dlclose loop (attach race) and tight-call hammers (LRU
 * eviction): separate handles from the main one, never reloaded. */
static const char *loop_provider;
static atomic_int loop_stop;
static atomic_ulong loop_count;
static void *hammer_handle;
static unsigned hammer_gen;
#define HAMMER_ITERS 50000UL

static void *looper(void *unused)
{
    (void)unused;
    /* dlmopen, not dlopen: reloading an already-loaded file only bumps a
     * refcount, while a fresh namespace churns real mappings. */
    while (!atomic_load(&loop_stop)) {
        void *h = dlmopen(LM_ID_NEWLM, loop_provider, RTLD_NOW | RTLD_LOCAL);
        if (!h)
            return (void *)1;
        dlclose(h);
        atomic_fetch_add(&loop_count, 1);
    }
    return NULL;
}

static void *hammer(void *arg)
{
    unsigned long iters = (unsigned long)arg;
    char info[256];
    slot_info_fn call = hammer_handle ? (slot_info_fn)dlsym(hammer_handle, "C_GetSlotInfo") : NULL;
    if (!call)
        return (void *)1;
    for (unsigned long i = 0; i < iters; i++)
        call(0x70000000UL + hammer_gen, info);
    return NULL;
}

static void *exec_self_thread(void *arg)
{
    const char *provider = arg;
    execl("/proc/self/exe", "instance-continuity", "cmd", provider, (char *)NULL);
    return (void *)1; /* execl failed */
}

/* Its own frame: vfork shares the parent's stack, so the caller's
 * registers must not hold live values across it (-Wclobbered). */
static int vfork_unmap_page(void *page)
{
    pid_t child = vfork();
    int status = 0;
    if (child < 0)
        return -1;
    if (child == 0) {
        int rc = munmap(page, 4096);
        _exit(rc == 0 ? 0 : 3);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static void *racer(void *unused)
{
    char info[256];
    (void)unused;
    while (!atomic_load(&race_stop)) {
        pthread_rwlock_rdlock(&image_lock);
        unsigned gen = atomic_load(&race_gen);
        slot_info_fn call = (slot_info_fn)dlsym(race_handle, "C_GetSlotInfo");
        if (call && gen < RACE_GENS) {
            call(0x72000000UL + gen, info);
            race_counts[gen]++;
        }
        pthread_rwlock_unlock(&image_lock);
        /* About 5k calls/s: dense around every boundary, bounded ring load. */
        struct timespec pause = { 0, 200000 };
        nanosleep(&pause, NULL);
    }
    return NULL;
}

static int cmd_mode(const char *provider)
{
    pthread_t race_thread;
    int racing = 0;
    pthread_t loop_thread;
    int looping = 0;
    void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    void *sibling = NULL;
    void *page = NULL;
    void *moved = NULL;
    void *split = NULL;
    unsigned gen = 0;
    struct stat st;
    char info[256];
    int unrelated;
    char path[] = "/proc/self/exe";

    if (!handle)
        die("dlopen");
    if (stat(provider, &st) != 0)
        die("stat");
    printf("READY %d %lx\n", getpid(), (unsigned long)base_of(handle));
    fflush(stdout);
    for (;;) {
        int command = getchar();
        if (command == EOF || command == 'x') {
            release_held_sharer();
            release_zombie_child();
            return 0;
        }
        switch (command) {
        case 'c': {
            slot_info_fn call = main_call(handle);
            if (!call)
                die("dlsym");
            printf("CALL %u %lu\n", gen, call(0x70000000UL + gen, info));
            break;
        }
        case 'C': {
            slot_info_fn call = sibling ? (slot_info_fn)dlsym(sibling, "C_GetSlotInfo") : NULL;
            if (!call)
                die("sibling dlsym");
            printf("SCALL %u %lu\n", gen, call(0x71000000UL + gen, info));
            break;
        }
        case 'r': {
            uintptr_t old = base_of(handle);
            pthread_rwlock_wrlock(&image_lock);
            if (dlclose(handle) != 0)
                die("dlclose");
            handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
            if (!handle)
                die("reopen");
            gen += 1;
            race_handle = handle;
            atomic_store(&race_gen, gen);
            pthread_rwlock_unlock(&image_lock);
            printf("RELOAD %u %lx %lx\n", gen, (unsigned long)old,
                   (unsigned long)base_of(handle));
            break;
        }
        case 'R':
            race_handle = handle;
            atomic_store(&race_gen, gen);
            atomic_store(&race_stop, 0);
            if (racing || pthread_create(&race_thread, NULL, racer, NULL) != 0)
                die("racer");
            racing = 1;
            printf("RACING\n");
            break;
        case 'S':
            if (!racing)
                die("not racing");
            atomic_store(&race_stop, 1);
            pthread_join(race_thread, NULL);
            racing = 0;
            printf("RACED");
            for (unsigned g = 0; g < RACE_GENS; g++)
                if (race_counts[g])
                    printf(" %u:%lu", g, race_counts[g]);
            printf("\n");
            break;
        case 'd':
            sibling = dlmopen(LM_ID_NEWLM, provider, RTLD_NOW | RTLD_LOCAL);
            if (!sibling)
                die("dlmopen");
            printf("SIBLING %lx\n", (unsigned long)base_of(sibling));
            break;
        case 'm':
            unrelated = open(path, O_RDONLY);
            if (unrelated < 0)
                die("open unrelated");
            page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, unrelated, 0);
            if (page == MAP_FAILED)
                die("mmap unrelated");
            munmap(page, 4096);
            page = NULL;
            close(unrelated);
            printf("UNRELATED\n");
            break;
        case 'p': {
            int fd = open(provider, O_RDONLY);
            if (fd < 0)
                die("open provider");
            page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
            if (page == MAP_FAILED)
                die("mmap provider");
            printf("PMAP\n");
            break;
        }
        case 'v': {
            static char stack[64 * 1024] __attribute__((aligned(16)));
            int status = 0;
            sharer_provider = provider;
            pid_t child = clone(sharer_child, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
            if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0)
                die("CLONE_VM sharer");
            printf("SHARER\n");
            break;
        }
        case 'w': {
            static char stack[64 * 1024] __attribute__((aligned(16)));
            if (held_sharer)
                die("sharer already held");
            /* CLOEXEC: an exec reaps this image's state (fresh BSS forgets
             * the sharer), so the pipe must not survive it — EOF wakes the
             * stranded child, which exits quietly. */
            if (pipe2(held_sharer_pipe, O_CLOEXEC) != 0)
                die("held sharer pipe");
            held_sharer_provider = provider;
            pid_t child = clone(held_sharer_child, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
            if (child < 0)
                die("CLONE_VM held sharer");
            held_sharer = child;
            printf("SHARER_HELD %d\n", (int)child);
            break;
        }
        case 'W': {
            int status = 0;
            if (!held_sharer)
                die("no held sharer");
            if (write(held_sharer_pipe[1], "g", 1) != 1)
                die("held sharer wake");
            if (waitpid(held_sharer, &status, 0) != held_sharer || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0)
                die("held sharer mutation");
            close(held_sharer_pipe[0]);
            close(held_sharer_pipe[1]);
            held_sharer_pipe[0] = held_sharer_pipe[1] = -1;
            held_sharer = 0;
            printf("SHARER_WOKE\n");
            break;
        }
        case 'z': {
            pid_t child;
            if (zombie_child)
                die("zombie already held");
            if (pipe2(zombie_wake, O_CLOEXEC) != 0)
                die("zombie wake pipe");
            zombie_provider = provider;
            child = fork();
            if (child < 0)
                die("zombie scenario fork");
            if (child == 0) {
                zombie_scenario_child();
                _exit(2);
            }
            zombie_child = child;
            close(zombie_wake[0]);
            zombie_wake[0] = -1;
            /* No reply here: the scenario child prints ZOMBIE_HELD itself. */
            break;
        }
        case 'Z': {
            int status = 0;
            if (!zombie_child)
                die("no zombie held");
            if (write(zombie_wake[1], "g", 1) != 1)
                die("zombie wake");
            if (waitpid(zombie_child, &status, 0) != zombie_child || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0)
                die("zombie scenario mutation");
            close(zombie_wake[1]);
            zombie_wake[1] = -1;
            zombie_child = 0;
            printf("ZOMBIE_WOKE\n");
            break;
        }
        case 'M': {
            /* Move the provider page (mremap -> copy_vma). MREMAP_DONTUNMAP
             * keeps the old VMA, so the move itself reaches no munmap hook;
             * the old page is unmapped separately afterwards. */
            void *moved;
            if (!page)
                die("mremap without page");
            moved = mremap(page, 4096, 4096, MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
            if (moved == MAP_FAILED)
                die("mremap provider");
            munmap(page, 4096);
            page = moved;
            printf("PMOVE\n");
            break;
        }
        case 'P':
            if (page)
                munmap(page, 4096);
            page = NULL;
            if (moved)
                munmap(moved, 4096);
            moved = NULL;
            printf("PUNMAP\n");
            break;
        case 'U': {
            /* Pure MREMAP_DONTUNMAP: the old VMA stays, so only the
             * copy_vma hook sees the new VMA. Both must stay mapped. */
            void *fresh;
            unsigned char vec;
            if (!page || moved)
                die("mremap without page");
            fresh = mremap(page, 4096, 4096, MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
            if (fresh == MAP_FAILED)
                die("mremap provider pure");
            if (mincore(page, 4096, &vec) != 0 || mincore(fresh, 4096, &vec) != 0)
                die("DONTUNMAP dropped a mapping");
            moved = fresh;
            printf("PUREMOVE\n");
            break;
        }
        case 'V':
            /* A true vfork child (parent suspended) unmapping the shared
             * provider page: the child is marked at fork, so the unmap
             * goes to the file's global epoch. */
            if (!page)
                die("vfork unmap without page");
            if (vfork_unmap_page(page) != 0)
                die("vfork child unmap");
            page = NULL;
            printf("VUNMAP\n");
            break;
        case 'h': {
            /* Another process (a forked child) punch-holes the provider
             * file's first page: the loaded image keeps executing from
             * untouched text while the header page's VMAs are zapped. */
            pid_t child;
            int status;
            child = fork();
            if (child < 0)
                die("fork for punch-hole");
            if (child == 0) {
                int fd = open(provider, O_RDWR);
                int rc = -1;
                if (fd >= 0) {
                    rc = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 4096);
                    close(fd);
                }
                _exit(rc == 0 ? 0 : 3);
            }
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0)
                die("punch-hole child");
            printf("PHOLE\n");
            break;
        }
        case 'e':
            /* Exec self: pipes survive, the driver restarts and prints
             * READY again with a reset generation. */
            execl("/proc/self/exe", "instance-continuity", "cmd", provider, (char *)NULL);
            die("exec self");
            break;
        case 'E': {
            /* A non-leader thread execs self: de_thread kills this main
             * thread, so the join below only returns when execl failed. */
            pthread_t thread;
            void *result = NULL;
            if (pthread_create(&thread, NULL, exec_self_thread, (void *)provider) != 0)
                die("exec thread");
            pthread_join(thread, &result);
            (void)result;
            die("nonleader exec returned");
            break;
        }
        case 'f': {
            pid_t child = fork();
            if (child < 0)
                die("fork");
            if (child == 0)
                _exit(0);
            if (waitpid(child, NULL, 0) != child)
                die("wait fork");
            printf("FORKED\n");
            break;
        }
        case 'L':
            loop_provider = provider;
            atomic_store(&loop_stop, 0);
            if (looping || pthread_create(&loop_thread, NULL, looper, NULL) != 0)
                die("loop thread");
            looping = 1;
            printf("LOOPING\n");
            break;
        case 'n':
            printf("LOOPCOUNT %lu\n", atomic_load(&loop_count));
            break;
        case 'l': {
            void *result = NULL;
            if (!looping)
                die("not looping");
            atomic_store(&loop_stop, 1);
            pthread_join(loop_thread, &result);
            looping = 0;
            if (result != NULL)
                die("loop iteration");
            printf("LOOPED %lu\n", atomic_load(&loop_count));
            break;
        }
        case 'H': {
            /* Two hammer threads, tight calls, async protocol: HAMMERING
             * now (the observer pumps while they run), HAMMERED when both
             * joined. No reloads run meanwhile, so no lock is needed. */
            pthread_t h1, h2;
            void *r1 = NULL, *r2 = NULL;
            hammer_handle = handle;
            hammer_gen = gen;
            if (pthread_create(&h1, NULL, hammer, (void *)HAMMER_ITERS) != 0)
                die("hammer1");
            if (pthread_create(&h2, NULL, hammer, (void *)HAMMER_ITERS) != 0)
                die("hammer2");
            printf("HAMMERING\n");
            fflush(stdout);
            pthread_join(h1, &r1);
            pthread_join(h2, &r2);
            hammer_handle = NULL;
            if (r1 != NULL || r2 != NULL)
                die("hammer call");
            printf("HAMMERED %lu\n", 2 * HAMMER_ITERS);
            break;
        }
        case 'D':
            /* MADV_DONTNEED of a provider mapping: drops private pages and
             * changes no VMA (the zap path still reaches uprobe_munmap). */
            if (!page || madvise(page, 4096, MADV_DONTNEED) != 0)
                die("madvise provider");
            printf("PDONTNEED\n");
            break;
        case 'F': {
            /* MAP_FIXED anonymous memory over the provider page: the file
             * VMA is replaced in place (a watched removal). */
            void *fixed;
            if (!page)
                die("MAP_FIXED without page");
            fixed = mmap(page, 4096, PROT_READ, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (fixed != page)
                die("MAP_FIXED over provider");
            munmap(fixed, 4096);
            page = NULL;
            printf("PFIXED\n");
            break;
        }
        case 'q': {
            int fd = open(provider, O_RDONLY);
            if (fd < 0 || split)
                die("open provider for split");
            split = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
            if (split == MAP_FAILED)
                die("mmap provider pair");
            printf("P2MAP\n");
            break;
        }
        case 's':
            /* A split-inducing mprotect of the second provider page. */
            if (!split || mprotect((char *)split + 4096, 4096, PROT_NONE) != 0)
                die("split mprotect");
            printf("PSPLIT\n");
            break;
        case 'Q':
            if (split)
                munmap(split, 8192);
            split = NULL;
            printf("P2UNMAP\n");
            break;
        default:
            continue;
        }
        fflush(stdout);
    }
}

/* ---- churn mode: SoftHSM2 long-lived key workload under unrelated churn ---- */

typedef struct {
    CK_ULONG type;
    void *value;
    CK_ULONG len;
} attribute;
typedef struct {
    CK_ULONG mechanism;
    void *parameter;
    CK_ULONG len;
} mechanism;
typedef CK_ULONG (*initialize_fn)(void *);
typedef CK_ULONG (*slot_list_fn)(unsigned char, CK_ULONG *, CK_ULONG *);
typedef CK_ULONG (*open_session_fn)(CK_ULONG, CK_ULONG, void *, void *, CK_ULONG *);
typedef CK_ULONG (*login_fn)(CK_ULONG, CK_ULONG, const char *, CK_ULONG);
typedef CK_ULONG (*generate_key_fn)(CK_ULONG, mechanism *, attribute *, CK_ULONG, CK_ULONG *);
typedef CK_ULONG (*encrypt_init_fn)(CK_ULONG, mechanism *, CK_ULONG);
typedef CK_ULONG (*encrypt_fn)(CK_ULONG, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
typedef CK_ULONG (*finalize_fn)(void *);

static atomic_int stop_churn;
static const char *churn_file;
static const char *churn_so;
static int churn_rate;
static uintptr_t text_start, text_end;
static unsigned long op_counts[7];
static unsigned long op_errors;

static int find_text(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    if (!info->dlpi_name || !strstr(info->dlpi_name, (const char *)data))
        return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X)) {
            uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
            uintptr_t end = start + phdr->p_memsz;
            text_start = start & ~(uintptr_t)4095;
            text_end = (end + 4095) & ~(uintptr_t)4095;
            return 1;
        }
    }
    return 0;
}

static void churn_op(unsigned index)
{
    void *p;
    switch (index % 7) {
    case 0:
        p = mmap(NULL, 256 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { op_errors++; return; }
        ((volatile char *)p)[0] = 1;
        munmap(p, 256 * 1024);
        break;
    case 1: {
        char *q = malloc(1 << 20);
        if (!q) { op_errors++; return; }
        q[0] = 1;
        char *r = realloc(q, 3 << 20); /* mmapped chunk: grows through mremap */
        if (!r) { free(q); op_errors++; return; }
        r[(3 << 20) - 1] = 1;
        free(r);
        break;
    }
    case 2:
        p = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { op_errors++; return; }
        if (mmap(p, 64 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                 -1, 0) == MAP_FAILED)
            op_errors++;
        munmap(p, 64 * 1024);
        break;
    case 3:
        p = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { op_errors++; return; }
        if (mprotect(p, 64 * 1024, PROT_READ) != 0)
            op_errors++;
        munmap(p, 64 * 1024);
        break;
    case 4: {
        int fd = open(churn_file, O_RDONLY);
        if (fd < 0) { op_errors++; return; }
        p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (p == MAP_FAILED) { op_errors++; return; }
        munmap(p, 4096);
        break;
    }
    case 5: {
        void *h = dlopen(churn_so, RTLD_NOW | RTLD_LOCAL);
        if (!h) { op_errors++; return; }
        dlclose(h);
        break;
    }
    case 6:
        if (!text_start || mprotect((void *)text_start, text_end - text_start,
                                    PROT_READ | PROT_EXEC) != 0)
            op_errors++;
        break;
    }
    op_counts[index % 7]++;
}

static void *churn_thread(void *unused)
{
    (void)unused;
    if (churn_rate <= 0)
        return NULL;
    uint64_t period = 1000000000ULL / (uint64_t)churn_rate;
    uint64_t next = now_ns();
    for (unsigned i = 0; !atomic_load(&stop_churn); i++) {
        churn_op(i);
        next += period;
        uint64_t now = now_ns();
        if (next > now) {
            struct timespec ts = { (time_t)((next - now) / 1000000000ULL),
                                   (long)((next - now) % 1000000000ULL) };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

#define SYM(type, name) type name = (type)dlsym(handle, #name); if (!name) die(#name)

static int churn_mode(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "usage: churn PROVIDER UNRELATED_FILE UNRELATED_SO SECONDS RATE\n");
        return 64;
    }
    const char *provider = argv[2];
    churn_file = argv[3];
    churn_so = argv[4];
    int seconds = atoi(argv[5]);
    churn_rate = atoi(argv[6]);
    void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        die("dlopen provider");
    SYM(initialize_fn, C_Initialize);
    SYM(slot_list_fn, C_GetSlotList);
    SYM(open_session_fn, C_OpenSession);
    SYM(login_fn, C_Login);
    SYM(generate_key_fn, C_GenerateKey);
    SYM(encrypt_init_fn, C_EncryptInit);
    SYM(encrypt_fn, C_Encrypt);
    SYM(slot_info_fn, C_GetSlotInfo);
    SYM(finalize_fn, C_Finalize);
    const char *leaf = strrchr(provider, '/');
    dl_iterate_phdr(find_text, (void *)(leaf ? leaf + 1 : provider));
    CK_ULONG slots[8], count = 8, session = 0, key = 0, rv;
    if ((rv = C_Initialize(NULL)) != 0) { printf("FAIL C_Initialize %lu\n", rv); return 2; }
    if ((rv = C_GetSlotList(1, slots, &count)) != 0 || count == 0) {
        printf("FAIL C_GetSlotList %lu %lu\n", rv, count); return 2;
    }
    if ((rv = C_OpenSession(slots[0], 0x4 | 0x2, NULL, NULL, &session)) != 0) {
        printf("FAIL C_OpenSession %lu\n", rv); return 2;
    }
    if ((rv = C_Login(session, 1, "1234", 4)) != 0) { printf("FAIL C_Login %lu\n", rv); return 2; }
    CK_ULONG value_len = 32;
    unsigned char yes = 1, no = 0;
    attribute tmpl[] = { { 0x161, &value_len, sizeof(value_len) },
                         { 0x104, &yes, 1 }, { 0x1, &no, 1 } };
    mechanism keygen = { 0x1080, NULL, 0 }, ecb = { 0x1081, NULL, 0 };
    if ((rv = C_GenerateKey(session, &keygen, tmpl, 3, &key)) != 0) {
        printf("FAIL C_GenerateKey %lu\n", rv); return 2;
    }
    uintptr_t base = base_of(handle);
    printf("READY %d %lx %lx %lx\n", getpid(), (unsigned long)base,
           (unsigned long)text_start, (unsigned long)text_end);
    printf("KEY session=%lu key=%lu\n", session, key);
    fflush(stdout);
    /* Wait for the observer to finish attaching. */
    if (getchar() != 'g')
        return 3;
    pthread_t churner;
    if (pthread_create(&churner, NULL, churn_thread, NULL) != 0)
        die("pthread_create");
    uint64_t deadline = now_ns() + (uint64_t)seconds * 1000000000ULL;
    unsigned long calls = 0, encrypts = 0, bad = 0;
    char info[256];
    unsigned char in[16] = { 0 }, out[64];
    while (now_ns() < deadline) {
        C_GetSlotInfo(0x70000000UL, info);
        calls++;
        CK_ULONG out_len = sizeof(out);
        if (C_EncryptInit(session, &ecb, key) != 0 || C_Encrypt(session, in, 16, out, &out_len) != 0)
            bad++;
        encrypts++;
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    atomic_store(&stop_churn, 1);
    pthread_join(churner, NULL);
    printf("LEDGER calls=%lu encrypts=%lu bad=%lu key=%lu base_start=%lx base_end=%lx\n", calls,
           encrypts, bad, key, (unsigned long)base, (unsigned long)base_of(handle));
    printf("OPS anon=%lu mremap=%lu fixed=%lu mprotect=%lu file=%lu dl=%lu ptext=%lu errors=%lu\n",
           op_counts[0], op_counts[1], op_counts[2], op_counts[3], op_counts[4], op_counts[5],
           op_counts[6], op_errors);
    fflush(stdout);
    /* Hold until the observer has drained, then finish. */
    if (getchar() != 'x')
        return 4;
    C_Finalize(NULL);
    return 0;
}

/* Nine-file overflow workload: argv[2 + n] is provider file n, all loaded
 * before any attach (unwatched, so unclaimed). Commands '0'-'8' reload
 * one file each, 'c' calls through file 8's handle. */
static int ovf_mode(int argc, char **argv)
{
    void *handles[9] = { NULL };
    char info[256];
    if (argc != 11)
        die("ovf usage");
    for (unsigned n = 0; n < 9; n++) {
        handles[n] = dlopen(argv[2 + n], RTLD_NOW | RTLD_LOCAL);
        if (!handles[n])
            die("ovf dlopen");
    }
    printf("READY %d\n", getpid());
    fflush(stdout);
    for (;;) {
        int command = getchar();
        if (command == EOF || command == 'x')
            return 0;
        if (command >= '0' && command <= '8') {
            unsigned n = (unsigned)(command - '0');
            if (handles[n] == NULL || dlclose(handles[n]) != 0)
                die("ovf dlclose");
            handles[n] = dlopen(argv[2 + n], RTLD_NOW | RTLD_LOCAL);
            if (!handles[n])
                die("ovf dlopen");
            printf("REOPENED %u\n", n);
        } else if (command == 'c') {
            slot_info_fn call =
                handles[8] ? (slot_info_fn)dlsym(handles[8], "C_GetSlotInfo") : NULL;
            if (!call)
                die("ovf dlsym");
            printf("CALL %lu\n", call(0x70000000UL, info));
        } else {
            continue;
        }
        fflush(stdout);
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 3 && strcmp(argv[1], "cmd") == 0)
        return cmd_mode(argv[2]);
    if (argc == 11 && strcmp(argv[1], "ovf") == 0)
        return ovf_mode(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "churn") == 0)
        return churn_mode(argc, argv);
    fprintf(stderr, "usage: instance-continuity cmd PROVIDER | ovf P0..P8 | churn ...\n");
    return 64;
}
#endif
