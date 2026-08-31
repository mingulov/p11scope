#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#define PTRACE_SYSCALL_INFO_NONE 0
#define PTRACE_SYSCALL_INFO_ENTRY 1
#define PTRACE_SYSCALL_INFO_EXIT 2
#define PTRACE_SYSCALL_INFO_SECCOMP 3
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

struct p11_ptrace_syscall_info {
    uint8_t op;
    uint8_t pad[3];
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct { uint64_t nr; uint64_t args[6]; } entry;
        struct { int64_t rval; uint8_t is_error; } exit;
    };
};

#define RECORD_SIZE 128U
#define MAX_RECORDS 8192U
#define MAX_TASKS 64U
#define MAX_CREATIONS 64U
#define MAX_PENDING_STOPS 64U
#define MAX_INVOCATIONS 65536U
#define INT_MAX_VALUE 2147483647

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "cleanup gate must be lock-free");

#define K_HEADER 0x01U
#define K_ROOT 0x10U
#define K_CREATE_ENTRY 0x11U
#define K_CREATE_EVENT 0x12U
#define K_CREATE_EXIT 0x13U
#define K_CHILD_JOIN 0x14U
#define K_VFORK_DONE 0x15U
#define K_EXEC_EVENT 0x16U
#define K_EXIT_EVENT 0x17U
#define K_FINAL_WIF 0x18U
#define K_SIGNAL_DELIVERY 0x19U
#define K_SYSCALL_CANCEL 0x1aU
#define K_FCNTL_ENTRY 0x20U
#define K_FCNTL_EXIT 0x21U

#define OPTS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
              PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE | \
              PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | \
              PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL)

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t received_signal;

struct journal {
    unsigned char *data;
    size_t count;
};

struct task {
    pid_t tid;
    uint64_t generation;
    uint64_t group;
    int live;
    int exited;
    int wif;
    int superseded;
    int exec_seen;
    int terminal_wait_pending;
    uint64_t terminal_deadline;
    int cleanup_exit_seen;
    int cleanup_parent_wif;
    uint64_t syscall_number;
    int syscall_entry;
    int creation;
    int fcntl;
    uint64_t fcntl_fd;
    uint64_t fcntl_command;
    uint64_t fcntl_argument;
    uint32_t exit_status;
};

struct creation {
    uint64_t number;
    uint64_t parent;
    uint16_t syscall_kind;
    uint16_t event_kind;
    uint64_t child_generation;
    pid_t child_tid;
    int event;
    int joined;
    int done;
    int result_seen;
    int cleanup_cancelled;
    int cleanup_child_wif;
    pid_t stop_tid;
    int child_stop;
    int collector_kill;
};

struct pending_stop {
    pid_t tid;
    uint64_t creation;
    int cleanup_resumed;
    int cleanup_exit_seen;
};

enum observation_kind {
    OBS_HEADER,
    OBS_ROOT,
    OBS_EXEC,
    OBS_SYSCALL_ENTRY,
    OBS_SYSCALL_EXIT,
    OBS_CREATE_EVENT,
    OBS_CHILD_STOP,
    OBS_VFORK_DONE,
    OBS_EXIT_EVENT,
    OBS_FINAL_WIF,
    OBS_SIGNAL_DELIVERY,
    OBS_COLLECTOR_KILL,
    OBS_TERMINAL_PENDING,
    OBS_CLEANUP_STOP,
    OBS_CLEANUP_UNKNOWN_STOP,
    OBS_CLEANUP_UNKNOWN_WIF,
    OBS_CLEANUP_WIF
};

#define SIGNAL_PHASE_ARM 1U
#define SIGNAL_PHASE_ORDINARY 2U
#define SIGNAL_PHASE_STOPPING 3U
#define SIGNAL_PHASE_EVENT_STOP 4U
#define SIGNAL_PHASE_CLEANUP 6U
#define SIGNAL_PHASE_GROUP_ARM 7U
#define SIGNAL_INFO_NONE 0U
#define SIGNAL_INFO_SUCCESS 1U
#define SIGNAL_INFO_EINVAL 2U
#define SIGNAL_INFO_ESRCH 3U

struct observation {
    enum observation_kind kind;
    uint64_t generation;
    uint64_t parent;
    uint64_t creation;
    uint64_t child;
    uint64_t group;
    uint64_t arguments[6];
    uint64_t invocation;
    uint16_t syscall_kind;
    uint16_t event_kind;
    uint16_t exec_class;
    uint16_t signal_phase;
    uint16_t signal_info;
    uint32_t status;
    long result;
    pid_t tid;
};

struct transition_actions {
    int set_options;
    int collector_kill;
    int contain_group;
    int hold;
    int resume;
    int resume_cont;
    int resume_signal;
    int deliver_signal;
    int signal_before_resume;
    pid_t signal_tid;
    pid_t action_tid;
    int reject;
};

struct collector {
    const char *case_name;
    int output_fd;
    int output_flags;
    int watchdog_fd;
    pid_t root;
    off_t output_offset;
    struct stat output_identity;
    struct stat executable_identity;
    struct stat stdin_identity;
    struct stat stdout_identity;
    struct stat stderr_identity;
    int stdin_flags;
    int stdout_flags;
    int stderr_flags;
    int bootstrap_identity_ready;
    struct journal journal;
    struct task tasks[MAX_TASKS];
    size_t task_count;
    struct creation creations[MAX_CREATIONS];
    size_t creation_count;
    struct pending_stop pending_stops[MAX_PENDING_STOPS];
    size_t pending_stop_count;
    uint64_t next_generation;
    uint64_t next_creation;
    uint64_t next_invocation;
    uint64_t next_group;
    int saw_exec;
    int header_seen;
    int root_seen;
    int signal_state;
    int restart_state;
    int expected_rejection;
    int restart_observed;
    int group_stop_state;
    int group_stop_observed;
    pid_t helper;
    pid_t helper_candidate;
    int helper_expected;
    int helper_go_fd;
    int helper_ack_fd;
    int helper_go_released;
    int helper_reaped;
    int helper_status;
    int helper_ack;
    int cleanup_exec_triggered;
    int cleanup_fault_observed;
    int flush_rollback_failed;
    uint64_t deadline;
    int wait_echild;
    int cleanup_mode;
};

static const unsigned char magic[8] = {'P', '1', '1', 'S', '9', 'R', '1', 0};

static void put16(unsigned char *p, uint16_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
}

static void put32(unsigned char *p, uint32_t value)
{
    for (unsigned int i = 0; i != 4; ++i)
        p[i] = (unsigned char)(value >> (8U * i));
}

static void put64(unsigned char *p, uint64_t value)
{
    for (unsigned int i = 0; i != 8; ++i)
        p[i] = (unsigned char)(value >> (8U * i));
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void latch_signal(int signal_number)
{
    stop_requested = 1;
    received_signal = signal_number;
}

static int tracee_getfd(void)
{
    return fcntl(STDERR_FILENO, F_GETFD, 0);
}

static void tracee_caught_signal(int signal_number)
{
    (void)signal_number;
    (void)tracee_getfd();
}

static int valid_case(const char *name)
{
    static const char *const cases[] = {
        "sim-event-first", "sim-stop-first", "sim-tid-reuse", "sim-restart",
        "review-policy-bpf", "kernel-bootstrap", "kernel-fork", "kernel-clone",
        "kernel-vfork", "kernel-nonleader-exec", "kernel-signal-ignored",
        "kernel-signal-caught", "kernel-restart-reject", "kernel-group-stop-reject",
        "kernel-cleanup-signal-int", "kernel-cleanup-signal-hup",
        "kernel-cleanup-signal-term", "kernel-cleanup-failure", NULL
    };
    for (size_t i = 0; cases[i] != NULL; ++i)
        if (strcmp(name, cases[i]) == 0)
            return 1;
    return 0;
}

static int cleanup_signal_for_case(const char *name)
{
    if (strcmp(name, "kernel-cleanup-signal-int") == 0)
        return SIGINT;
    if (strcmp(name, "kernel-cleanup-signal-hup") == 0)
        return SIGHUP;
    if (strcmp(name, "kernel-cleanup-signal-term") == 0)
        return SIGTERM;
    return 0;
}

static int valid_kernel_case(const char *name)
{
    return strncmp(name, "kernel-", 7) == 0 && valid_case(name);
}

static int valid_internal_workload_case(const char *name)
{
    return valid_kernel_case(name);
}

static int parse_fd(const char *text, int *result)
{
    unsigned long value = 0;
    if (text == NULL || *text == 0 || (text[0] == '0' && text[1] != 0))
        return -1;
    for (const unsigned char *p = (const unsigned char *)text; *p != 0; ++p) {
        if (*p < '0' || *p > '9')
            return -1;
        value = value * 10U + (unsigned long)(*p - '0');
        if (value > INT_MAX_VALUE)
            return -1;
    }
    if (value < 3U)
        return -1;
    *result = (int)value;
    return 0;
}

static int same_file(struct stat *a, struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int validate_output(int fd, off_t *offset, struct stat *identity, int *flags_out)
{
    struct stat st;
    int flags;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 07777) != 0600 || st.st_nlink != 1 || st.st_size != 0)
        return -1;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDWR || (flags & O_APPEND) != 0)
        return -1;
    *offset = lseek(fd, 0, SEEK_CUR);
    if (*offset < 0)
        return -1;
    if (identity != NULL)
        *identity = st;
    if (flags_out != NULL)
        *flags_out = flags;
    return 0;
}

static int same_output_identity(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
           a->st_gid == b->st_gid && a->st_mode == b->st_mode && a->st_nlink == b->st_nlink;
}

static int same_executable_identity(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           (a->st_mode & S_IFMT) == (b->st_mode & S_IFMT);
}

static int snapshot_bootstrap_identity(struct collector *collector)
{
    struct stat null_identity;
    int stdin_flags;
    int stdout_flags;
    int stderr_flags;
    if (stat("/proc/self/exe", &collector->executable_identity) != 0 ||
        !S_ISREG(collector->executable_identity.st_mode) ||
        stat("/dev/null", &null_identity) != 0 || fstat(STDIN_FILENO, &collector->stdin_identity) != 0 ||
        fstat(STDOUT_FILENO, &collector->stdout_identity) != 0 ||
        fstat(STDERR_FILENO, &collector->stderr_identity) != 0 ||
        (collector->stdin_identity.st_dev != null_identity.st_dev ||
         collector->stdin_identity.st_ino != null_identity.st_ino) ||
        !S_ISCHR(collector->stdin_identity.st_mode) ||
        (collector->stdout_identity.st_dev == collector->stderr_identity.st_dev &&
         collector->stdout_identity.st_ino == collector->stderr_identity.st_ino))
        return -1;
    stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
    stdout_flags = fcntl(STDOUT_FILENO, F_GETFL);
    stderr_flags = fcntl(STDERR_FILENO, F_GETFL);
    if (stdin_flags < 0 || stdout_flags < 0 || stderr_flags < 0 ||
        (stdin_flags & O_ACCMODE) != O_RDONLY ||
        !S_ISREG(collector->stdout_identity.st_mode) ||
        !S_ISREG(collector->stderr_identity.st_mode) ||
        collector->stdout_identity.st_uid != geteuid() ||
        collector->stderr_identity.st_uid != geteuid() ||
        (collector->stdout_identity.st_mode & 07777) != 0600 ||
        (collector->stderr_identity.st_mode & 07777) != 0600 ||
        collector->stdout_identity.st_nlink != 1 || collector->stderr_identity.st_nlink != 1)
        return -1;
    collector->stdin_flags = stdin_flags;
    collector->stdout_flags = stdout_flags;
    collector->stderr_flags = stderr_flags;
    collector->bootstrap_identity_ready = 1;
    return 0;
}

static int tracee_fd_flags(pid_t tid, int fd, int *flags_out)
{
    char path[64];
    char data[256];
    ssize_t count;
    int info_fd;
    int flags;
    int parsed = 0;
    int length = snprintf(path, sizeof(path), "/proc/%ld/fdinfo/%d", (long)tid, fd);
    if (length < 0 || (size_t)length >= sizeof(path))
        return -1;
    info_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (info_fd < 0)
        return -1;
    count = read(info_fd, data, sizeof(data) - 1U);
    close(info_fd);
    if (count <= 0)
        return -1;
    data[count] = 0;
    if (sscanf(data, "pos:%*u\nflags:%o", &flags) != 1)
        return -1;
    parsed = 1;
    if (parsed)
        *flags_out = flags;
    return 0;
}

static int bootstrap_fd_set_valid(const int seen[3])
{
    return seen[0] && seen[1] && seen[2];
}

static int probe_result_success(int result)
{
    return result >= 0 ? 0 : -1;
}

static int probe_result_denied(int result, int error)
{
    return result < 0 && error == EPERM ? 0 : -1;
}

static int verify_tracee_bootstrap(const struct collector *collector, pid_t tid)
{
    char path[64];
    char fd_path[64];
    DIR *directory;
    struct dirent *entry;
    struct stat actual;
    int seen[3] = {0, 0, 0};
    int flags;
    int length;
    if (!collector->bootstrap_identity_ready)
        return -1;
    length = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)tid);
    if (length < 0 || (size_t)length >= sizeof(path) || stat(path, &actual) != 0 ||
        !same_executable_identity(&actual, &collector->executable_identity))
        return -1;
    length = snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd", (long)tid);
    if (length < 0 || (size_t)length >= sizeof(fd_path))
        return -1;
    directory = opendir(fd_path);
    if (directory == NULL)
        return -1;
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        unsigned long number;
        if (entry->d_name[0] == '.')
            continue;
        errno = 0;
        number = strtoul(entry->d_name, &end, 10);
        if (errno != 0 || *end != 0 || number > 2U || seen[number]) {
            closedir(directory);
            return -1;
        }
        seen[number] = 1;
    }
    if (closedir(directory) != 0 || !bootstrap_fd_set_valid(seen))
        return -1;
    for (int fd = 0; fd != 3; ++fd) {
        length = snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long)tid, fd);
        if (length < 0 || (size_t)length >= sizeof(path) || stat(path, &actual) != 0)
            return -1;
        if (fd == 0) {
            if (!same_executable_identity(&actual, &collector->stdin_identity) ||
                tracee_fd_flags(tid, fd, &flags) != 0 || flags != collector->stdin_flags)
                return -1;
        } else if (fd == 1) {
            if (!same_executable_identity(&actual, &collector->stdout_identity) ||
                tracee_fd_flags(tid, fd, &flags) != 0 || flags != collector->stdout_flags)
                return -1;
        } else if (!same_executable_identity(&actual, &collector->stderr_identity) ||
                   tracee_fd_flags(tid, fd, &flags) != 0 || flags != collector->stderr_flags) {
            return -1;
        }
    }
    return 0;
}

static int validate_watchdog(int fd, int output_fd)
{
    struct stat st;
    int flags;
    if (fd == output_fd || fd <= 2 || fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode))
        return -1;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY || (flags & O_APPEND) != 0)
        return -1;
    for (int i = 0; i != 3; ++i) {
        struct stat standard;
        if (fstat(i, &standard) == 0 && same_file(&st, &standard))
            return -1;
    }
    return 0;
}

static int journal_push(struct journal *journal, uint16_t kind, size_t payload_end,
                        void (*payload)(unsigned char *))
{
    unsigned char *record;
    if (journal->count >= MAX_RECORDS || payload_end > RECORD_SIZE)
        return -1;
    record = journal->data + journal->count * RECORD_SIZE;
    memset(record, 0, RECORD_SIZE);
    memcpy(record, magic, sizeof(magic));
    put16(record + 8, 1);
    put16(record + 10, kind);
    put64(record + 16, journal->count);
    if (payload != NULL)
        payload(record);
    if (payload_end < RECORD_SIZE)
        memset(record + payload_end, 0, RECORD_SIZE - payload_end);
    journal->count++;
    return 0;
}

struct p_header { uint32_t size; uint32_t endian; };
static struct p_header header_payload;
static void fill_header(unsigned char *r)
{
    put32(r + 24, header_payload.size);
    put32(r + 28, header_payload.endian);
}

static uint64_t payload_a;
static uint64_t payload_b;
static uint64_t payload_c;
static uint64_t payload_d;
static uint64_t payload_args[6];
static uint16_t payload_kind;
static uint16_t payload_kind2;
static uint32_t payload_status;

static void fill_one(unsigned char *r) { put64(r + 24, payload_a); }
static void fill_three(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    put64(r + 40, payload_c);
}
static void fill_create_entry(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    put16(r + 40, payload_kind);
}
static void fill_create_event(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    put16(r + 40, payload_kind);
}
static void fill_create_exit(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    put16(r + 40, payload_kind);
    put16(r + 42, payload_kind2);
}
static void fill_join(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    put64(r + 40, payload_c);
    put64(r + 48, payload_d);
    put16(r + 56, payload_kind);
}
static void fill_exec(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    put64(r + 40, payload_c);
    put16(r + 48, payload_kind);
}
static void fill_status(unsigned char *r)
{
    put64(r + 24, payload_a);
    put32(r + 32, payload_status);
}
static void fill_fcntl_entry(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    for (size_t i = 0; i != 6; ++i)
        put64(r + 40U + 8U * i, payload_args[i]);
}
static void fill_fcntl_exit(unsigned char *r)
{
    put64(r + 24, payload_a);
    put64(r + 32, payload_b);
    put64(r + 40, payload_c);
}

static int add_header(struct journal *journal)
{
    header_payload.size = RECORD_SIZE;
    header_payload.endian = 0x01020304U;
    return journal_push(journal, K_HEADER, 32, fill_header);
}

static int add_root(struct journal *journal)
{
    payload_a = 1;
    return journal_push(journal, K_ROOT, 32, fill_one);
}

static int add_exec(struct journal *journal, uint64_t execing, uint64_t displaced,
                    uint64_t group, uint16_t class)
{
    payload_a = execing;
    payload_b = displaced;
    payload_c = group;
    payload_kind = class;
    return journal_push(journal, K_EXEC_EVENT, 50, fill_exec);
}

static int add_creation_entry(struct journal *journal, uint64_t creation, uint64_t parent,
                              uint16_t syscall_kind)
{
    payload_a = creation;
    payload_b = parent;
    payload_kind = syscall_kind;
    return journal_push(journal, K_CREATE_ENTRY, 42, fill_create_entry);
}

static int add_creation_event(struct journal *journal, uint64_t creation, uint64_t parent,
                              uint16_t event_kind)
{
    payload_a = creation;
    payload_b = parent;
    payload_kind = event_kind;
    return journal_push(journal, K_CREATE_EVENT, 42, fill_create_event);
}

static int add_creation_exit(struct journal *journal, uint64_t creation, uint64_t parent,
                             int success, uint16_t error)
{
    payload_a = creation;
    payload_b = parent;
    payload_kind = success ? 1 : 0;
    payload_kind2 = error;
    return journal_push(journal, K_CREATE_EXIT, 44, fill_create_exit);
}

static int add_join(struct journal *journal, uint64_t creation, uint64_t parent,
                    uint64_t child, uint64_t group, uint16_t event_kind)
{
    payload_a = creation;
    payload_b = parent;
    payload_c = child;
    payload_d = group;
    payload_kind = event_kind;
    return journal_push(journal, K_CHILD_JOIN, 58, fill_join);
}

static int add_vfork_done(struct journal *journal, uint64_t creation, uint64_t parent,
                          uint64_t child)
{
    payload_a = creation;
    payload_b = parent;
    payload_c = child;
    return journal_push(journal, K_VFORK_DONE, 48, fill_three);
}

static int add_status(struct journal *journal, uint16_t kind, uint64_t generation,
                      uint32_t status)
{
    payload_a = generation;
    payload_status = status;
    return journal_push(journal, kind, 36, fill_status);
}

static int add_signal(struct journal *journal, uint64_t generation, int signal_number)
{
    payload_a = generation;
    payload_status = (uint32_t)signal_number;
    return journal_push(journal, K_SIGNAL_DELIVERY, 36, fill_status);
}

static int add_fcntl_entry(struct journal *journal, uint64_t invocation, uint64_t generation,
                           const uint64_t arguments[6])
{
    payload_a = invocation;
    payload_b = generation;
    memcpy(payload_args, arguments, sizeof(payload_args));
    return journal_push(journal, K_FCNTL_ENTRY, 88, fill_fcntl_entry);
}

static int add_fcntl_exit(struct journal *journal, uint64_t invocation, uint64_t generation,
                          uint64_t result)
{
    payload_a = invocation;
    payload_b = generation;
    payload_c = result;
    return journal_push(journal, K_FCNTL_EXIT, 48, fill_fcntl_exit);
}

static struct task *find_task(struct collector *collector, pid_t tid);
static struct task *find_generation(struct collector *collector, uint64_t generation);
static struct task *add_task(struct collector *collector, pid_t tid, uint64_t group);
static struct creation *find_creation(struct collector *collector, int number);
static struct creation *add_creation(struct collector *collector, struct task *parent,
                                     uint16_t syscall_kind);

static struct task *find_any_task(struct collector *collector, pid_t tid)
{
    for (size_t i = collector->task_count; i != 0; --i)
        if (collector->tasks[i - 1U].tid == tid)
            return &collector->tasks[i - 1U];
    return NULL;
}

static struct creation *creation_for_child(struct collector *collector, uint64_t generation)
{
    for (size_t i = 0; i != collector->creation_count; ++i) {
        struct creation *creation = &collector->creations[i];
        if (creation->joined && creation->child_generation == generation)
            return creation;
    }
    return NULL;
}

static int pending_stop_index(const struct collector *collector, pid_t tid)
{
    for (size_t i = 0; i != collector->pending_stop_count; ++i)
        if (collector->pending_stops[i].tid == tid)
            return (int)i;
    return -1;
}

static int pending_stop_add(struct collector *collector, pid_t tid)
{
    if (tid <= 0 || pending_stop_index(collector, tid) >= 0 ||
        collector->pending_stop_count >= MAX_PENDING_STOPS)
        return -1;
    memset(&collector->pending_stops[collector->pending_stop_count], 0,
           sizeof(collector->pending_stops[collector->pending_stop_count]));
    collector->pending_stops[collector->pending_stop_count++].tid = tid;
    return 0;
}

static void pending_stop_remove(struct collector *collector, pid_t tid)
{
    int index = pending_stop_index(collector, tid);
    if (index < 0)
        return;
    collector->pending_stops[(size_t)index] =
        collector->pending_stops[--collector->pending_stop_count];
}

static int is_restart_result(long result)
{
    return result == -512L || result == -513L || result == -514L || result == -516L;
}

static int is_stopping_signal(int signal_number)
{
    return signal_number == SIGSTOP || signal_number == SIGTSTP ||
           signal_number == SIGTTIN || signal_number == SIGTTOU;
}

static int expected_signal_for_case(const struct collector *collector)
{
    if (strcmp(collector->case_name, "kernel-signal-ignored") == 0)
        return SIGUSR1;
    if (strcmp(collector->case_name, "kernel-signal-caught") == 0)
        return SIGUSR2;
    return 0;
}

static int is_expected_kernel_restart(const struct collector *collector,
                                      const struct task *task, long result)
{
    return strcmp(collector->case_name, "kernel-restart-reject") == 0 &&
           !collector->restart_observed && task->generation == 1 &&
           task->tid == collector->root && task->live &&
           !task->exited && !task->wif && !task->superseded && task->syscall_entry &&
           task->syscall_number == SYS_fcntl && task->fcntl > 0 &&
           (uint64_t)task->fcntl < collector->next_invocation &&
           task->fcntl_command == F_SETLKW &&
           collector->restart_state == 1 && result == -512L;
}

static int cleanup_failure_ready(const struct collector *collector)
{
    const struct task *root = NULL;
    const struct task *peer = NULL;
    const struct creation *fork_creation;
    if (strcmp(collector->case_name, "kernel-cleanup-failure") != 0 ||
        collector->task_count != 2 || collector->creation_count != 1 ||
        !collector->root_seen || !collector->saw_exec ||
        collector->cleanup_mode || collector->cleanup_fault_observed ||
        collector->pending_stop_count != 0)
        return 0;
    for (size_t i = 0; i != collector->task_count; ++i) {
        const struct task *task = &collector->tasks[i];
        if (task->generation == 1)
            root = task;
        else
            peer = task;
    }
    if (root == NULL || peer == NULL || root->tid != collector->root ||
        !root->live || root->exited || root->wif || root->superseded ||
        root->terminal_wait_pending || root->cleanup_exit_seen || root->cleanup_parent_wif ||
        root->syscall_number != SYS_fcntl || !root->syscall_entry || root->creation != 0 ||
        root->fcntl == 0 || root->fcntl_fd != STDERR_FILENO ||
        root->fcntl_command != F_GETFD || root->fcntl_argument != 0)
        return 0;
    if (!peer->live || peer->exited || peer->wif || peer->superseded ||
        peer->terminal_wait_pending || peer->cleanup_exit_seen || peer->cleanup_parent_wif ||
        peer->syscall_entry || peer->syscall_number != 0 || peer->creation != 0 ||
        peer->fcntl != 0)
        return 0;
    fork_creation = &collector->creations[0];
    if (fork_creation->parent != root->generation ||
        (fork_creation->syscall_kind != 1 && fork_creation->syscall_kind != 3) ||
        fork_creation->event_kind != 1 || !fork_creation->event || !fork_creation->joined ||
        !fork_creation->result_seen || fork_creation->done || fork_creation->child_stop ||
        fork_creation->stop_tid != peer->tid || fork_creation->child_tid != peer->tid ||
        fork_creation->child_generation != peer->generation || fork_creation->cleanup_cancelled ||
        fork_creation->collector_kill)
        return 0;
    return 1;
}

static int terminal_deadline_expired(const struct collector *collector)
{
    for (size_t i = 0; i != collector->task_count; ++i)
        if (collector->tasks[i].terminal_wait_pending &&
            monotonic_ns() >= collector->tasks[i].terminal_deadline)
            return 1;
    return 0;
}

static int transition_join(struct collector *collector, struct creation *creation,
                           pid_t child, struct transition_actions *actions)
{
    struct task *parent = find_generation(collector, creation->parent);
    struct task *child_task;
    uint64_t group;
    if (parent == NULL || creation->joined || !creation->event ||
        creation->child_stop == 0 || creation->stop_tid != child)
        return -1;
    if (collector->task_count >= MAX_TASKS || find_task(collector, child) != NULL ||
        collector->journal.count >= MAX_RECORDS)
        return -1;
    group = creation->event_kind == 1 || creation->event_kind == 2
                ? ++collector->next_group : parent->group;
    child_task = add_task(collector, child, group);
    if (child_task == NULL)
        return -1;
    creation->child_tid = child;
    creation->child_generation = child_task->generation;
    creation->joined = 1;
    creation->child_stop = 0;
    actions->set_options = 1;
    actions->action_tid = child;
    return add_join(&collector->journal, creation->number, parent->generation,
                    child_task->generation, group, creation->event_kind);
}

static int mark_terminal_pending(struct collector *collector, uint64_t generation);

static int transition(struct collector *collector, const struct observation *observation,
                      struct transition_actions *actions)
{
    struct task *task;
    struct creation *creation;
    memset(actions, 0, sizeof(*actions));
    switch (observation->kind) {
    case OBS_HEADER:
        if (collector->header_seen)
            return -1;
        collector->header_seen = 1;
        return add_header(&collector->journal);
    case OBS_ROOT:
        if (!collector->header_seen || collector->root_seen ||
            find_generation(collector, 1) != NULL || collector->journal.count >= MAX_RECORDS)
            return -1;
        if (add_task(collector, collector->root, 1) == NULL)
            return -1;
        collector->root_seen = 1;
        return add_root(&collector->journal);
    case OBS_EXEC:
        task = find_generation(collector, observation->generation);
        if (!collector->root_seen || task == NULL || task->superseded)
            return -1;
        if (observation->exec_class == 1) {
            int bootstrap = !collector->saw_exec && task->generation == 1;
            if (!task->live || task->exited || task->wif || task->exec_seen ||
                (!collector->saw_exec && !bootstrap) ||
                (!bootstrap && (!task->syscall_entry || task->syscall_number != SYS_execve)) ||
                (bootstrap && (task->syscall_entry || task->syscall_number != 0 ||
                               task->fcntl != 0 || task->creation != 0)))
                return -1;
            collector->saw_exec = 1;
            task->exec_seen = 1;
            task->syscall_entry = 1;
            task->syscall_number = SYS_execve;
            return add_exec(&collector->journal, task->generation, 0, task->group, 1);
        }
        if (observation->exec_class == 2) {
            struct task *displaced = find_any_task(collector, observation->tid);
            struct task *execing = find_task(collector, (pid_t)observation->child);
            pid_t former_tid;
            if (!collector->saw_exec || displaced == NULL || execing == NULL || displaced == execing ||
                displaced->live || !displaced->exited || displaced->wif ||
                displaced->superseded || displaced->fcntl != 0 ||
                displaced->creation != 0 || !execing->live || execing->exited ||
                execing->wif || execing->superseded || !execing->syscall_entry ||
                execing->syscall_number != SYS_execve ||
                execing->fcntl != 0 || execing->creation != 0 ||
                displaced->group != execing->group)
                return -1;
            former_tid = execing->tid;
            if (add_exec(&collector->journal, execing->generation,
                    displaced->generation, execing->group, 2) != 0)
                return -1;
            displaced->superseded = 1;
            displaced->tid = former_tid;
            execing->tid = observation->tid;
            execing->exec_seen = 1;
            return 0;
        }
        return -1;
    case OBS_SYSCALL_ENTRY:
        if ((observation->syscall_kind == 5) != (observation->parent == SYS_fcntl))
            return -1;
        task = find_generation(collector, observation->generation);
        if (task == NULL || !task->live || task->superseded || task->exited || task->wif ||
            task->syscall_entry)
            return -1;
        if (observation->syscall_kind >= 1 && observation->syscall_kind <= 4) {
            if (task->creation != 0 ||
                (creation = add_creation(collector, task, observation->syscall_kind)) == NULL)
                return -1;
            if (add_creation_entry(&collector->journal, creation->number,
                    task->generation, observation->syscall_kind) != 0)
                return -1;
            task->creation = (int)creation->number;
        } else if (observation->syscall_kind == 5) {
            if (task->fcntl != 0 || observation->invocation == 0 ||
                observation->invocation != collector->next_invocation ||
                collector->next_invocation > MAX_INVOCATIONS ||
                collector->journal.count >= MAX_RECORDS)
                return -1;
            if (add_fcntl_entry(&collector->journal, observation->invocation,
                    task->generation, observation->arguments) != 0)
                return -1;
            task->fcntl = (int)observation->invocation;
            task->fcntl_fd = observation->arguments[0];
            task->fcntl_command = observation->arguments[1];
            task->fcntl_argument = observation->arguments[2];
            collector->next_invocation++;
        }
        task->syscall_entry = 1;
        task->syscall_number = observation->parent;
        return 0;
    case OBS_SYSCALL_EXIT: {
        int creation_failure;
        uint64_t invocation;
        task = find_generation(collector, observation->generation);
        if (task == NULL)
            return -1;
        if (is_restart_result(observation->result)) {
            if (is_expected_kernel_restart(collector, task, observation->result))
                collector->restart_observed = 1;
            actions->reject = 1;
            return -2;
        }
        if (!task->live || task->superseded || task->exited || task->wif ||
            !task->syscall_entry)
            return -1;
        creation = NULL;
        creation_failure = 0;
        if (task->creation != 0) {
            creation = find_creation(collector, task->creation);
            if (creation == NULL)
                return -1;
            if (observation->result < 0 && observation->result >= -4095) {
                if (creation->event || creation->joined || creation->done ||
                    creation->result_seen || creation->child_tid != 0 ||
                    creation->child_generation != 0 || creation->stop_tid != 0 ||
                    creation->child_stop)
                    return -1;
                creation_failure = 1;
            } else if (!creation->event ||
                       observation->result != (long)creation->child_tid ||
                       creation->result_seen ||
                       (creation->syscall_kind == 2 && !creation->done)) {
                return -1;
            }
            if (collector->journal.count >= MAX_RECORDS)
                return -1;
        } else if (task->fcntl != 0) {
            if (collector->journal.count >= MAX_RECORDS)
                return -1;
        }
        task->syscall_entry = 0;
        if (creation != NULL) {
            if (creation_failure) {
                creation->result_seen = 1;
                if (add_creation_exit(&collector->journal, creation->number,
                        task->generation, 0, (uint16_t)-observation->result) != 0)
                    return -1;
            } else {
                creation->result_seen = 1;
                if (add_creation_exit(&collector->journal, creation->number,
                        task->generation, 1, 0) != 0)
                    return -1;
            }
            task->creation = 0;
        }
        if (task->fcntl != 0) {
            invocation = (uint64_t)task->fcntl;
            if (add_fcntl_exit(&collector->journal, invocation, task->generation,
                    (uint64_t)observation->result) != 0)
                return -1;
            if (observation->result == 0 && task->fcntl_command == F_GETFD &&
                (creation = creation_for_child(collector, task->generation)) != NULL &&
                creation->syscall_kind == 3 && creation->event_kind == 3 &&
                !creation->collector_kill)
                actions->collector_kill = 1;
            task->fcntl = 0;
            task->fcntl_fd = 0;
        }
        task->syscall_number = 0;
        return 0;
    }
    case OBS_CREATE_EVENT:
        {
        int pending_stop;
        task = find_generation(collector, observation->generation);
        creation = find_creation(collector, (int)observation->creation);
        pending_stop = pending_stop_index(collector, observation->tid);
        if (task == NULL || !task->live || task->superseded || task->exited || task->wif ||
            creation == NULL || creation->parent != task->generation ||
            task->creation != (int)observation->creation ||
            creation->event ||
            (creation->syscall_kind == 1 && observation->event_kind != 1) ||
            (creation->syscall_kind == 2 && observation->event_kind != 2) ||
            (creation->syscall_kind == 4 && observation->event_kind != 3) ||
            (creation->syscall_kind == 3 && observation->event_kind != 1 &&
             observation->event_kind != 3) ||
            (creation->syscall_kind < 1 || creation->syscall_kind > 4) ||
            find_task(collector, observation->tid) != NULL ||
            (creation->child_tid != 0 && creation->child_tid != observation->tid) ||
            (creation->stop_tid != 0 && creation->stop_tid != observation->tid) ||
            (pending_stop >= 0 && collector->pending_stops[(size_t)pending_stop].creation != 0 &&
             collector->pending_stops[(size_t)pending_stop].creation != creation->number))
            return -1;
        if (collector->journal.count >= MAX_RECORDS)
            return -1;
        creation->event = 1;
        creation->event_kind = observation->event_kind;
        creation->child_tid = observation->tid;
        creation->stop_tid = observation->tid;
        if (add_creation_event(&collector->journal, creation->number,
                task->generation, observation->event_kind) != 0)
            return -1;
        if (pending_stop >= 0) {
            collector->pending_stops[(size_t)pending_stop].creation = creation->number;
            creation->child_stop = 1;
        }
        if (creation->child_stop) {
            int result = transition_join(collector, creation, observation->tid, actions);
            if (result == 0) {
                if (pending_stop >= 0)
                    pending_stop_remove(collector, observation->tid);
                if (pending_stop >= 0)
                    actions->resume = 1;
            }
            return result;
        }
        return 0;
        }
    case OBS_CHILD_STOP:
        creation = NULL;
        if (observation->creation != 0) {
            creation = find_creation(collector, (int)observation->creation);
            if (creation == NULL)
                return -1;
            task = find_generation(collector, creation->parent);
            if (task == NULL || !task->live || task->creation != (int)observation->creation)
                return -1;
        } else {
            for (size_t i = 0; i != collector->creation_count; ++i) {
                struct creation *candidate = &collector->creations[i];
                if (candidate->stop_tid == observation->tid && !candidate->joined) {
                    creation = candidate;
                    break;
                }
            }
        }
        if (creation == NULL) {
            if (find_any_task(collector, observation->tid) != NULL ||
                pending_stop_add(collector, observation->tid) != 0)
                return -1;
            actions->hold = 1;
            return 0;
        }
        if (creation->joined ||
            (creation->stop_tid != 0 && creation->stop_tid != observation->tid))
            return -1;
        creation->child_stop = 1;
        if (creation->stop_tid == 0)
            creation->stop_tid = observation->tid;
        if (creation->event)
            return transition_join(collector, creation, observation->tid, actions);
        return 0;
    case OBS_VFORK_DONE:
        {
        struct task *parent;
        creation = NULL;
        for (size_t i = 0; i != collector->creation_count; ++i)
            if (collector->creations[i].event_kind == 2 &&
                collector->creations[i].child_tid == observation->tid)
                creation = &collector->creations[i];
        parent = creation == NULL ? NULL : find_generation(collector, creation->parent);
        if (creation == NULL || creation->done || !creation->joined || creation->result_seen ||
            parent == NULL || !parent->live || parent->creation != (int)creation->number ||
            collector->journal.count >= MAX_RECORDS)
            return -1;
        creation->done = 1;
        return add_vfork_done(&collector->journal, creation->number, creation->parent,
                              creation->child_generation);
        }
    case OBS_COLLECTOR_KILL:
        creation = creation_for_child(collector, observation->generation);
        if (creation == NULL || !creation->joined || creation->event_kind != 3 ||
            (creation->syscall_kind != 3 && creation->syscall_kind != 4) ||
            creation->collector_kill)
            return -1;
        creation->collector_kill = 1;
        return 0;
    case OBS_TERMINAL_PENDING:
        task = find_generation(collector, observation->generation);
        if (task == NULL || task->superseded || task->wif || task->terminal_wait_pending)
            return -1;
        task->terminal_wait_pending = 1;
        task->terminal_deadline = monotonic_ns() + 5000000000ULL;
        if (collector->deadline != 0 && task->terminal_deadline > collector->deadline)
            task->terminal_deadline = collector->deadline;
        return 0;
    case OBS_CLEANUP_STOP:
        task = find_generation(collector, observation->generation);
        if (task == NULL || task->wif || task->superseded)
            return -1;
        if (observation->event_kind == PTRACE_EVENT_EXIT) {
            if (task->cleanup_exit_seen)
                return -1;
            task->cleanup_exit_seen = 1;
        }
        return 0;
    case OBS_CLEANUP_UNKNOWN_STOP:
        if (observation->tid <= 0 || find_any_task(collector, observation->tid) != NULL)
            return -1;
        {
            int pending = pending_stop_index(collector, observation->tid);
            struct creation *bound = NULL;
            for (size_t i = 0; i != collector->creation_count; ++i) {
                struct creation *candidate = &collector->creations[i];
                if (candidate->event && !candidate->joined &&
                    candidate->stop_tid == observation->tid) {
                    if (bound != NULL)
                        return -1;
                    bound = candidate;
                }
            }
            if (pending >= 0) {
                struct pending_stop *entry = &collector->pending_stops[(size_t)pending];
                if (entry->creation != 0 &&
                    (bound == NULL || entry->creation != bound->number))
                    return -1;
                if (entry->creation == 0 && bound != NULL)
                    entry->creation = bound->number;
                if (observation->event_kind == PTRACE_EVENT_EXIT) {
                    if (entry->cleanup_exit_seen)
                        return -1;
                    entry->cleanup_exit_seen = 1;
                    entry->cleanup_resumed = 0;
                } else {
                    if (entry->cleanup_exit_seen || !entry->cleanup_resumed)
                        return -1;
                    entry->cleanup_resumed = 0;
                }
            } else {
                if (pending_stop_add(collector, observation->tid) != 0)
                    return -1;
                {
                    struct pending_stop *entry =
                        &collector->pending_stops[collector->pending_stop_count - 1U];
                    entry->creation = bound == NULL ? 0 : bound->number;
                    entry->cleanup_exit_seen = observation->event_kind == PTRACE_EVENT_EXIT;
                }
            }
        }
        actions->hold = 1;
        return 0;
    case OBS_CLEANUP_UNKNOWN_WIF:
        if (!collector->cleanup_mode || observation->tid <= 0 ||
            find_any_task(collector, observation->tid) != NULL)
            return -1;
        {
            int pending = pending_stop_index(collector, observation->tid);
            struct creation *bound = NULL;
            for (size_t i = 0; i != collector->creation_count; ++i) {
                struct creation *candidate = &collector->creations[i];
                if (candidate->event && !candidate->joined &&
                    candidate->child_tid == observation->tid) {
                    if (bound != NULL)
                        return -1;
                    bound = candidate;
                }
            }
            if (pending < 0 && bound == NULL)
                return -1;
            if (pending >= 0) {
                struct pending_stop *entry = &collector->pending_stops[(size_t)pending];
                if (entry->creation != 0) {
                    creation = find_creation(collector, (int)entry->creation);
                    if (creation == NULL || (bound != NULL && creation != bound))
                        return -1;
                    bound = creation;
                } else if (bound != NULL) {
                    entry->creation = bound->number;
                }
            }
            if (bound != NULL) {
                if (bound->cleanup_child_wif)
                    return -1;
                bound->cleanup_child_wif = 1;
                bound->cleanup_cancelled = 1;
                bound->child_stop = 0;
            }
            if (pending >= 0)
                pending_stop_remove(collector, observation->tid);
        }
        return 0;
    case OBS_CLEANUP_WIF:
        task = find_generation(collector, observation->generation);
        if (task == NULL)
            return -1;
        if (task->wif) {
            if (!collector->cleanup_mode || task->cleanup_parent_wif ||
                task->exit_status != observation->status)
                return -1;
            task->cleanup_parent_wif = 1;
            return 0;
        }
        if (task->creation != 0) {
            creation = find_creation(collector, task->creation);
            if (creation == NULL)
                return -1;
            creation->cleanup_cancelled = 1;
            creation->child_stop = 0;
            task->creation = 0;
        }
        task->terminal_wait_pending = 0;
        task->terminal_deadline = 0;
        task->syscall_entry = 0;
        task->syscall_number = 0;
        task->fcntl = 0;
        task->fcntl_fd = 0;
        task->exit_status = observation->status;
        task->exited = 1;
        task->live = 0;
        task->wif = 1;
        return 0;
    case OBS_EXIT_EVENT:
        task = find_generation(collector, observation->generation);
        if (task == NULL || !task->live || task->superseded || task->exited || task->wif ||
            task->fcntl != 0 || task->creation != 0 || collector->journal.count >= MAX_RECORDS)
            return -1;
        if (task->syscall_entry) {
            if (task->syscall_number != SYS_exit && task->syscall_number != SYS_exit_group)
                return -1;
            task->syscall_entry = 0;
            task->syscall_number = 0;
        }
        creation = creation_for_child(collector, task->generation);
        if (creation != NULL && creation->collector_kill && observation->status != 9)
            return -1;
        task->exit_status = observation->status;
        task->exited = 1;
        task->live = 0;
        return add_status(&collector->journal, K_EXIT_EVENT, task->generation,
                          observation->status);
    case OBS_FINAL_WIF:
        task = find_generation(collector, observation->generation);
        if (task == NULL || task->superseded || task->wif ||
            task->fcntl != 0 ||
            task->creation != 0 || collector->journal.count >= MAX_RECORDS)
            return -1;
        if (!task->terminal_wait_pending && task->syscall_entry)
            return -1;
        creation = creation_for_child(collector, task->generation);
        if (task->live && !task->terminal_wait_pending &&
            (task->syscall_entry || creation == NULL || !creation->collector_kill))
            return -1;
        if (!task->exited && !task->terminal_wait_pending) {
            if (creation == NULL || !creation->collector_kill || observation->status != 9)
                return -1;
            task->exited = 1;
            task->live = 0;
        } else if (task->exited && task->exit_status != observation->status) {
            return -1;
        }
        task->terminal_wait_pending = 0;
        task->terminal_deadline = 0;
        task->syscall_entry = 0;
        task->syscall_number = 0;
        task->live = 0;
        task->exited = 1;
        task->wif = 1;
        return add_status(&collector->journal, K_FINAL_WIF, task->generation,
                          observation->status);
    case OBS_SIGNAL_DELIVERY:
        task = find_generation(collector, observation->generation);
        if (task == NULL) {
            actions->reject = 1;
            return -1;
        }
        if (observation->signal_phase == SIGNAL_PHASE_ARM) {
            int expected_signal = expected_signal_for_case(collector);
            if (expected_signal == 0 || task->superseded || !task->live || task->exited ||
                task->wif ||
                collector->signal_state != 0 ||
                observation->status != (uint32_t)expected_signal) {
                actions->reject = 1;
                return -1;
            }
            collector->signal_state = 1;
            actions->resume = 1;
            actions->deliver_signal = (int)observation->status;
            actions->signal_before_resume = 1;
            actions->signal_tid = task->tid;
            return 0;
        }
        if (observation->signal_phase == SIGNAL_PHASE_GROUP_ARM) {
            if (task->superseded || !task->live || task->exited || task->wif ||
                collector->group_stop_state != 0 || observation->status != SIGSTOP) {
                actions->reject = 1;
                return -1;
            }
            collector->group_stop_state = 1;
            actions->resume = 1;
            actions->deliver_signal = SIGSTOP;
            actions->signal_tid = -collector->root;
            return 0;
        }
        if (observation->signal_phase == SIGNAL_PHASE_CLEANUP) {
            creation = creation_for_child(collector, task->generation);
            if (task->superseded || !task->live || task->exited || task->wif ||
                observation->status != SIGKILL || creation == NULL || !creation->collector_kill) {
                actions->reject = 1;
                return -1;
            }
            if (add_signal(&collector->journal, task->generation, SIGKILL) != 0)
                return -1;
            actions->resume = 1;
            actions->resume_signal = SIGKILL;
            return 0;
        }
        if (observation->signal_phase == SIGNAL_PHASE_EVENT_STOP) {
            if (task->superseded || !task->live || task->exited || task->wif ||
                !is_stopping_signal((int)observation->status)) {
                actions->reject = 1;
                return -1;
            }
            if (observation->status == SIGSTOP && collector->group_stop_state == 2) {
                collector->group_stop_state = 3;
                collector->group_stop_observed = 1;
            }
            actions->reject = 1;
            return -2;
        }
        if (observation->signal_phase == SIGNAL_PHASE_ORDINARY) {
            if (task->superseded || !task->live || task->exited || task->wif ||
                observation->status == 0 || observation->status >= NSIG ||
                observation->status == SIGKILL || is_stopping_signal((int)observation->status) ||
                observation->signal_info != SIGNAL_INFO_NONE) {
                actions->reject = 1;
                return -1;
            }
        } else if (observation->signal_phase == SIGNAL_PHASE_STOPPING) {
            if (task->superseded || !task->live || task->exited || task->wif ||
                !is_stopping_signal((int)observation->status)) {
                actions->reject = 1;
                return -1;
            }
            if (observation->signal_info == SIGNAL_INFO_ESRCH)
                return mark_terminal_pending(collector, task->generation) == 0 ? -3 : -1;
            if (observation->signal_info == SIGNAL_INFO_EINVAL) {
                actions->reject = 1;
                if (observation->status == SIGSTOP && collector->group_stop_state == 2) {
                    collector->group_stop_state = 3;
                    collector->group_stop_observed = 1;
                }
                return -2;
            }
            if (observation->signal_info != SIGNAL_INFO_SUCCESS) {
                actions->reject = 1;
                return -1;
            }
            if (observation->status == SIGSTOP && collector->group_stop_state == 1)
                collector->group_stop_state = 2;
        } else {
            actions->reject = 1;
            return -1;
        }
        if (add_signal(&collector->journal, task->generation, (int)observation->status) != 0)
            return -1;
        if (collector->signal_state == 1 &&
            observation->status == (uint32_t)expected_signal_for_case(collector))
            collector->signal_state = 2;
        actions->resume = 1;
        actions->resume_signal = (int)observation->status;
        return 0;
    }
    return -1;
}

static int mark_terminal_pending(struct collector *collector, uint64_t generation)
{
    struct observation observation;
    struct transition_actions actions;
    if (generation == 0)
        return -1;
    memset(&observation, 0, sizeof(observation));
    observation.kind = OBS_TERMINAL_PENDING;
    observation.generation = generation;
    return transition(collector, &observation, &actions);
}

static int flush_journal(struct collector *collector)
{
    struct stat before;
    struct stat after;
    int truncate_result;
    size_t bytes = collector->journal.count * RECORD_SIZE;
    off_t offset_before;
    off_t offset_after;
    int flags;
    if (fstat(collector->output_fd, &before) != 0 ||
        !same_output_identity(&before, &collector->output_identity) || before.st_size != 0 ||
        bytes == 0 || bytes > 128U * 1024U * 1024U)
        goto failed;
    flags = fcntl(collector->output_fd, F_GETFL);
    offset_before = lseek(collector->output_fd, 0, SEEK_CUR);
    if (flags < 0 || flags != collector->output_flags || offset_before != collector->output_offset)
        goto failed;
    for (size_t offset = 0; offset < bytes;) {
        ssize_t written = pwrite(collector->output_fd, collector->journal.data + offset,
                                 bytes - offset, (off_t)offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            goto failed;
        offset += (size_t)written;
    }
    if (fsync(collector->output_fd) != 0 || fstat(collector->output_fd, &after) != 0)
        goto failed;
    flags = fcntl(collector->output_fd, F_GETFL);
    offset_after = lseek(collector->output_fd, 0, SEEK_CUR);
    if (!same_output_identity(&after, &collector->output_identity) || after.st_size != (off_t)bytes ||
        flags != collector->output_flags || offset_after != collector->output_offset)
        goto failed;
    return 0;
failed:
    truncate_result = ftruncate(collector->output_fd, 0);
    if (truncate_result != 0 || fsync(collector->output_fd) != 0)
        collector->flush_rollback_failed = 1;
    return -1;
}

static int write_watchdog(int fd, int owned, pid_t root)
{
    unsigned char record[24] = {'P', '1', '1', 'S', '9', 'W', 'D', 0};
    put16(record + 8, 1);
    put16(record + 10, (uint16_t)(owned ? 1 : 0));
    put64(record + 16, owned ? (uint64_t)root : 0);
    for (size_t offset = 0; offset != sizeof(record);) {
        ssize_t written = write(fd, record + offset, sizeof(record) - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return close(fd);
}

static int wait_ready(int fd, uint64_t deadline)
{
    unsigned char marker;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    for (;;) {
        ssize_t count = read(fd, &marker, 1);
        if (count == 1)
            break;
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (monotonic_ns() >= deadline)
                return -1;
            {
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
                nanosleep(&pause, NULL);
            }
            continue;
        }
        return -1;
    }
    for (;;) {
        ssize_t count = read(fd, &marker, 1);
        if (count == 0)
            return 0;
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (monotonic_ns() >= deadline)
                return -1;
            {
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
                nanosleep(&pause, NULL);
            }
            continue;
        }
        return -1;
    }
}

static int wait_ack(int fd, unsigned char expected, uint64_t deadline)
{
    unsigned char marker;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    for (;;) {
        ssize_t count = read(fd, &marker, 1);
        if (count == 1)
            break;
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (monotonic_ns() >= deadline)
                return -1;
            {
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
                nanosleep(&pause, NULL);
            }
            continue;
        }
        return -1;
    }
    if (marker != expected)
        return -1;
    for (;;) {
        ssize_t count = read(fd, &marker, 1);
        if (count == 0)
            return 0;
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (monotonic_ns() >= deadline)
                return -1;
            {
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
                nanosleep(&pause, NULL);
            }
            continue;
        }
        return -1;
    }
}

static void close_if_open(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static int arm_pdeath(pid_t expected_parent)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
        return -1;
    if (expected_parent <= 1)
        return -1;
    return getppid() == expected_parent ? 0 : -1;
}

static void cleanup_helper_child(pid_t expected_parent, pid_t root_pid, pid_t collector_pid,
                                 int go_read, int go_write, int ack_read, int ack_write,
                                 int ready_read, int release_write,
                                 int signal_number)
{
    unsigned char marker;
    ssize_t count;
    if (arm_pdeath(expected_parent) != 0)
        _exit(120);
    if (go_write >= 0)
        close(go_write);
    if (ack_read >= 0)
        close(ack_read);
    if (ready_read >= 0)
        close(ready_read);
    if (release_write >= 0)
        close(release_write);
    if (setpgid(0, root_pid) != 0 || getpgid(0) != root_pid)
        _exit(120);
    do {
        count = read(go_read, &marker, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 1)
        _exit(120);
    do {
        count = read(go_read, &marker, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 0)
        _exit(120);
    if (close(go_read) != 0 || getppid() != expected_parent ||
        kill(collector_pid, signal_number) != 0)
        _exit(121);
    marker = 1;
    if (write(ack_write, &marker, 1) != 1 || close(ack_write) != 0)
        _exit(122);
    _exit(0);
}

static int release_cleanup_helper(struct collector *collector)
{
    unsigned char marker = 1;
    if (collector->helper < 0 || collector->helper_go_released ||
        collector->helper_go_fd < 0)
        return -1;
    if (write(collector->helper_go_fd, &marker, 1) != 1 ||
        close(collector->helper_go_fd) != 0)
        return -1;
    collector->helper_go_fd = -1;
    collector->helper_go_released = 1;
    collector->cleanup_exec_triggered = 1;
    return 0;
}

static int deny_rule(scmp_filter_ctx ctx, const char *name)
{
    int number = seccomp_syscall_resolve_name(name);
    if (number < 0)
        return 0;
    return seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 0);
}

static scmp_filter_ctx build_policy(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    static const char *const denied[] = {
        "socket", "connect", "bind", "listen", "accept", "accept4",
        "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "pidfd_getfd", "ptrace",
        "process_vm_readv", "process_vm_writev", "process_madvise", "kcmp",
        "io_uring_setup", "io_uring_enter", "io_uring_register", "open_by_handle_at",
        "kill", "tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo",
        "pidfd_send_signal", "setsid", "setpgid", NULL
    };
    if (ctx == NULL)
        return NULL;
    for (size_t i = 0; denied[i] != NULL; ++i) {
        if (deny_rule(ctx, denied[i]) != 0) {
            seccomp_release(ctx);
            return NULL;
        }
    }
    {
        int number = seccomp_syscall_resolve_name("clone");
        if (number >= 0 && seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, (scmp_datum_t)CLONE_UNTRACED,
                        (scmp_datum_t)CLONE_UNTRACED)) != 0) {
            seccomp_release(ctx);
            return NULL;
        }
    }
    {
        int number = seccomp_syscall_resolve_name("socketpair");
        if (number >= 0) {
            if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 1,
                    SCMP_A0(SCMP_CMP_NE, AF_UNIX)) != 0 ||
                seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 1,
                    SCMP_A1(SCMP_CMP_NE, SOCK_SEQPACKET | SOCK_CLOEXEC)) != 0 ||
                seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 1,
                    SCMP_A2(SCMP_CMP_NE, 0)) != 0) {
                seccomp_release(ctx);
                return NULL;
            }
        }
    }
    return ctx;
}

static int install_policy(void)
{
    scmp_filter_ctx ctx = build_policy();
    int result;
    if (ctx == NULL || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        if (ctx != NULL)
            seccomp_release(ctx);
        return -1;
    }
    result = seccomp_load(ctx);
    seccomp_release(ctx);
    return result;
}

static int probe_socketpair_success(int socket_type, int protocol)
{
    int pair[2] = {-1, -1};
    int first_close;
    int second_close;
    int result = socketpair(AF_UNIX, socket_type, protocol, pair);
    if (result != 0)
        return -1;
    first_close = close(pair[0]);
    second_close = close(pair[1]);
    return first_close == 0 && second_close == 0 ? 0 : -1;
}

static int probe_socketpair_not_eperm(int socket_type, int protocol)
{
    int pair[2] = {-1, -1};
    int error;
    errno = 0;
    if (socketpair(AF_UNIX, socket_type, protocol, pair) == 0) {
        if (close(pair[0]) != 0 || close(pair[1]) != 0)
            return -1;
        return 0;
    }
    error = errno;
    return error == EPERM ? -1 : 0;
}

static int probe_socketpair_denied(int socket_type, int protocol)
{
    int pair[2] = {-1, -1};
    errno = 0;
    if (socketpair(AF_UNIX, socket_type, protocol, pair) == 0) {
        close(pair[0]);
        close(pair[1]);
        return -1;
    }
    return errno == EPERM ? 0 : -1;
}

static int probe_socketpair_roundtrip(void)
{
    int pair[2] = {-1, -1};
    unsigned char sent = 0x5a;
    unsigned char received = 0;
    ssize_t count;
    int first_close;
    int second_close;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0)
        return -1;
    count = sendto(pair[0], &sent, 1, 0, NULL, 0);
    if (count != 1) {
        close(pair[0]);
        close(pair[1]);
        return -1;
    }
    count = recvfrom(pair[1], &received, 1, 0, NULL, NULL);
    if (count != 1 || received != sent) {
        close(pair[0]);
        close(pair[1]);
        return -1;
    }
    first_close = close(pair[0]);
    second_close = close(pair[1]);
    return first_close == 0 && second_close == 0 ? 0 : -1;
}

static int probe_policy(void)
{
    int fd;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe_result_success(fd) != 0)
        return -1;
    close(fd);
    if (probe_socketpair_success(SOCK_SEQPACKET | SOCK_CLOEXEC, 0) != 0 ||
        probe_socketpair_success(SOCK_STREAM | SOCK_CLOEXEC, 0) != 0 ||
        probe_socketpair_success(SOCK_DGRAM | SOCK_CLOEXEC, 0) != 0 ||
        probe_socketpair_success(SOCK_SEQPACKET, 0) != 0 ||
        probe_socketpair_not_eperm(SOCK_SEQPACKET | SOCK_CLOEXEC, 1) != 0)
        return -1;
    if (install_policy() != 0)
        return -1;
    errno = 0;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe_result_denied(fd, errno) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    if (fd >= 0) {
        close(fd);
        return -1;
    }
    if (probe_socketpair_roundtrip() != 0 ||
        probe_socketpair_denied(SOCK_STREAM | SOCK_CLOEXEC, 0) != 0 ||
        probe_socketpair_denied(SOCK_DGRAM | SOCK_CLOEXEC, 0) != 0 ||
        probe_socketpair_denied(SOCK_SEQPACKET, 0) != 0 ||
        probe_socketpair_denied(SOCK_SEQPACKET | SOCK_CLOEXEC, 1) != 0)
        return -1;
    return 0;
}

static int export_policy(struct collector *collector)
{
    struct stat before;
    struct stat after;
    scmp_filter_ctx ctx = build_policy();
    off_t offset_before;
    off_t offset_after;
    off_t original_offset = collector->output_offset;
    int flags;
    int result = -1;
    if (ctx == NULL)
        return -1;
    if (fstat(collector->output_fd, &before) != 0 ||
        !same_output_identity(&before, &collector->output_identity) || before.st_size != 0)
        goto failed;
    flags = fcntl(collector->output_fd, F_GETFL);
    offset_before = lseek(collector->output_fd, 0, SEEK_CUR);
    if (flags < 0 || flags != collector->output_flags || offset_before != original_offset)
        goto failed;
    if (lseek(collector->output_fd, 0, SEEK_SET) < 0 ||
        seccomp_export_bpf(ctx, collector->output_fd) != 0 ||
        fsync(collector->output_fd) != 0 ||
        fstat(collector->output_fd, &after) != 0)
        goto failed;
    flags = fcntl(collector->output_fd, F_GETFL);
    offset_after = lseek(collector->output_fd, 0, SEEK_CUR);
    if (!same_output_identity(&after, &collector->output_identity) || after.st_size <= 0 ||
        after.st_size > (off_t)(128U * 1024U * 1024U) || offset_after != after.st_size ||
        flags != collector->output_flags ||
        lseek(collector->output_fd, original_offset, SEEK_SET) != original_offset)
        goto failed;
    flags = fcntl(collector->output_fd, F_GETFL);
    offset_after = lseek(collector->output_fd, 0, SEEK_CUR);
    if (flags != collector->output_flags || offset_after != original_offset)
        goto failed;
    result = 0;
failed:
    seccomp_release(ctx);
    if (result != 0) {
        int truncate_result = ftruncate(collector->output_fd, 0);
        int sync_result = fsync(collector->output_fd);
        int restore_result = lseek(collector->output_fd, original_offset, SEEK_SET);
        if (truncate_result != 0 || sync_result != 0 || restore_result != original_offset)
            collector->flush_rollback_failed = 1;
    }
    return result;
}

static struct task *find_task(struct collector *collector, pid_t tid)
{
    for (size_t i = collector->task_count; i != 0; --i)
        if (collector->tasks[i - 1U].tid == tid && collector->tasks[i - 1U].live)
            return &collector->tasks[i - 1U];
    return NULL;
}

static struct task *find_generation(struct collector *collector, uint64_t generation)
{
    for (size_t i = 0; i != collector->task_count; ++i)
        if (collector->tasks[i].generation == generation)
            return &collector->tasks[i];
    return NULL;
}

static struct task *add_task(struct collector *collector, pid_t tid, uint64_t group)
{
    struct task *task;
    if (collector->task_count >= MAX_TASKS || find_task(collector, tid) != NULL)
        return NULL;
    task = &collector->tasks[collector->task_count++];
    memset(task, 0, sizeof(*task));
    task->tid = tid;
    task->generation = collector->next_generation++;
    task->group = group;
    task->live = 1;
    return task;
}

static struct creation *find_creation(struct collector *collector, int number)
{
    if (number <= 0 || (size_t)number > collector->creation_count)
        return NULL;
    return &collector->creations[(size_t)number - 1U];
}

static struct creation *add_creation(struct collector *collector, struct task *parent,
                                     uint16_t syscall_kind)
{
    struct creation *creation;
    if (collector->creation_count >= MAX_CREATIONS)
        return NULL;
    creation = &collector->creations[collector->creation_count++];
    memset(creation, 0, sizeof(*creation));
    creation->number = collector->next_creation++;
    creation->parent = parent->generation;
    creation->syscall_kind = syscall_kind;
    parent->creation = (int)creation->number;
    return creation;
}

static uint16_t event_kind(unsigned int event)
{
    if (event == PTRACE_EVENT_FORK)
        return 1;
    if (event == PTRACE_EVENT_VFORK)
        return 2;
    return 3;
}

static int set_options(pid_t tid)
{
    return ptrace(PTRACE_SETOPTIONS, tid, 0, (void *)(uintptr_t)OPTS);
}

static int resume_syscall(pid_t tid, int signal_number)
{
    return ptrace(PTRACE_SYSCALL, tid, 0, (void *)(uintptr_t)signal_number);
}

static int resume_cont(pid_t tid, int signal_number)
{
    return ptrace(PTRACE_CONT, tid, 0, (void *)(uintptr_t)signal_number);
}

static int action_esrch(struct collector *collector, struct task *action_task,
                        uint64_t generation)
{
    if (action_task == NULL && generation == 0)
        return collector->cleanup_mode ? 0 : -1;
    if (action_task != NULL && action_task->terminal_wait_pending)
        return 0;
    return mark_terminal_pending(collector,
        action_task == NULL ? generation : action_task->generation);
}

static int execute_actions(struct collector *collector, pid_t tid, uint64_t generation,
                           struct transition_actions *actions)
{
    struct task *action_task = find_any_task(collector, tid);
    pid_t action_tid = actions->action_tid > 0 ? actions->action_tid : tid;
    if (actions->action_tid > 0)
        action_task = find_any_task(collector, action_tid);
    if (actions->contain_group) {
        if (kill(-action_tid, SIGKILL) != 0 && errno != ESRCH)
            return -1;
        actions->contain_group = 0;
    }
    if (actions->set_options) {
        if (set_options(action_tid) != 0) {
            if (errno != ESRCH)
                return -1;
            if (action_esrch(collector, action_task, generation) != 0)
                return -1;
            memset(actions, 0, sizeof(*actions));
            actions->hold = 1;
            return 0;
        }
    }
    if (actions->collector_kill) {
        if (kill(action_tid, SIGKILL) != 0) {
            if (errno != ESRCH)
                return -1;
            if (action_esrch(collector, action_task, generation) != 0)
                return -1;
            memset(actions, 0, sizeof(*actions));
            actions->hold = 1;
            return 0;
        }
        {
            struct observation observation;
            memset(&observation, 0, sizeof(observation));
            observation.kind = OBS_COLLECTOR_KILL;
            observation.generation = generation;
            if (transition(collector, &observation, actions) != 0)
                return -1;
        }
        actions->hold = 1;
    }
    if (actions->deliver_signal && actions->signal_before_resume) {
        pid_t signal_tid = actions->signal_tid != 0 ? actions->signal_tid : action_tid;
        if (kill(signal_tid, actions->deliver_signal) != 0) {
            if (errno != ESRCH || action_esrch(collector, action_task, generation) != 0)
                return -1;
            memset(actions, 0, sizeof(*actions));
            actions->hold = 1;
            return 0;
        }
    }
    if (actions->resume) {
        int result = actions->resume_cont
                         ? resume_cont(action_tid, actions->resume_signal)
                         : resume_syscall(action_tid, actions->resume_signal);
        if (result != 0) {
            if (errno != ESRCH)
                return -1;
            if (action_esrch(collector, action_task, generation) != 0)
                return -1;
            memset(actions, 0, sizeof(*actions));
            actions->hold = 1;
        }
    }
    if (actions->deliver_signal && !actions->signal_before_resume) {
        pid_t signal_tid = actions->signal_tid != 0 ? actions->signal_tid : action_tid;
        if (kill(signal_tid, actions->deliver_signal) != 0) {
            if (errno != ESRCH || action_esrch(collector, action_task, generation) != 0)
                return -1;
            memset(actions, 0, sizeof(*actions));
            actions->hold = 1;
        }
    }
    return 0;
}

static int process_syscall(struct collector *collector, struct task *task, int entering,
                           const struct p11_ptrace_syscall_info *info)
{
    struct observation observation;
    struct transition_actions actions;
    uint64_t number = entering ? info->entry.nr : 0;
    memset(&observation, 0, sizeof(observation));
    observation.generation = task->generation;
    if (entering) {
        uint16_t creation_kind = 0;
        if (number == SYS_fork)
            creation_kind = 1;
        else if (number == SYS_vfork)
            creation_kind = 2;
        else if (number == SYS_clone)
            creation_kind = 3;
#ifdef SYS_clone3
        else if (number == SYS_clone3)
            creation_kind = 4;
#endif
        observation.kind = OBS_SYSCALL_ENTRY;
        observation.parent = number;
        observation.syscall_kind = creation_kind;
        memcpy(observation.arguments, info->entry.args, sizeof(observation.arguments));
        if (number == SYS_fcntl) {
            observation.syscall_kind = 5;
            observation.invocation = collector->next_invocation;
        }
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        if (number == SYS_fcntl && cleanup_failure_ready(collector)) {
            collector->cleanup_fault_observed = 1;
            return -2;
        }
        return execute_actions(collector, task->tid, task->generation, &actions) == 0 ? 0 : -1;
    }
    observation.kind = OBS_SYSCALL_EXIT;
    observation.result = (long)info->exit.rval;
    if (transition(collector, &observation, &actions) != 0)
        return actions.reject ? -2 : -1;
    if (execute_actions(collector, task->tid, task->generation, &actions) != 0)
        return -1;
    return actions.hold ? -3 : 0;
}

static int process_event(struct collector *collector, struct task *task, unsigned int event)
{
    unsigned long message = 0;
    if (ptrace(PTRACE_GETEVENTMSG, task->tid, 0, &message) != 0) {
        if (errno == ESRCH && mark_terminal_pending(collector, task->generation) == 0)
            return -3;
        return -1;
    }
    if (event == PTRACE_EVENT_EXIT) {
        struct observation observation;
        struct transition_actions actions;
        if (message > UINT32_MAX)
            return -1;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_EXIT_EVENT;
        observation.generation = task->generation;
        observation.status = (uint32_t)message;
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        return execute_actions(collector, task->tid, task->generation, &actions) == 0 ? 0 : -1;
    }
    if (event == PTRACE_EVENT_EXEC) {
        struct observation observation;
        struct transition_actions actions;
        if (!collector->saw_exec && verify_tracee_bootstrap(collector, task->tid) != 0)
            return -1;
        int first_exec = !collector->saw_exec;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_EXEC;
        observation.generation = task->generation;
        observation.exec_class = 1;
        if (!first_exec && strcmp(collector->case_name, "kernel-nonleader-exec") == 0) {
            if (message == 0 || message > INT_MAX_VALUE)
                return -1;
            observation.exec_class = 2;
            observation.tid = task->tid;
            observation.child = message;
        }
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        if (execute_actions(collector, task->tid, task->generation, &actions) != 0)
            return -1;
        if (first_exec) {
            if (cleanup_signal_for_case(collector->case_name) != 0 &&
                release_cleanup_helper(collector) != 0)
                return -1;
        }
        return 0;
    }
    if (event == PTRACE_EVENT_VFORK_DONE) {
        struct observation observation;
        struct transition_actions actions;
        if (message == 0 || message > INT_MAX_VALUE)
            return -1;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_VFORK_DONE;
        observation.tid = (pid_t)message;
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        return execute_actions(collector, task->tid, task->generation, &actions) == 0 ? 0 : -1;
    }
    if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
        event == PTRACE_EVENT_CLONE) {
        struct observation observation;
        struct transition_actions actions;
        if (message == 0 || message > INT_MAX_VALUE || task->creation == 0)
            return -1;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_CREATE_EVENT;
        observation.generation = task->generation;
        observation.creation = (uint64_t)task->creation;
        observation.event_kind = event_kind(event);
        observation.tid = (pid_t)message;
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        return execute_actions(collector, task->tid, task->generation, &actions) == 0 ? 0 : -1;
    }
    return -1;
}

static int containment_closed(const struct collector *collector);
static int lifecycle_complete(const struct collector *collector);

enum drain_mode {
    DRAIN_INITIAL_STOP,
    DRAIN_NORMAL,
    DRAIN_CLEANUP
};

static int handle_wait(struct collector *collector, pid_t tid, int status);

static int begin_cleanup(struct collector *collector, pid_t root)
{
    struct transition_actions actions;
    collector->cleanup_mode = 1;
    memset(&actions, 0, sizeof(actions));
    actions.contain_group = 1;
    if (execute_actions(collector, root, 0, &actions) != 0)
        return -1;
    for (size_t i = 0; i != collector->pending_stop_count; ++i) {
        struct pending_stop *entry = &collector->pending_stops[i];
        if (entry->cleanup_resumed)
            continue;
        entry->cleanup_resumed = 1;
        memset(&actions, 0, sizeof(actions));
        actions.resume = 1;
        actions.resume_cont = 1;
        if (execute_actions(collector, entry->tid, 0, &actions) != 0)
            return -1;
    }
    return 0;
}

static int drain_wait(struct collector *collector, enum drain_mode mode, pid_t root,
                      int *initial_status)
{
    int terminal_failure = 0;
    if (collector->deadline == 0 || root <= 0)
        return -1;
    if (mode == DRAIN_CLEANUP && begin_cleanup(collector, root) != 0)
        return -1;
    for (;;) {
        int status;
        pid_t tid;
        if (terminal_deadline_expired(collector) || monotonic_ns() >= collector->deadline)
            return -1;
        if (mode == DRAIN_NORMAL && cleanup_signal_for_case(collector->case_name) != 0 &&
            stop_requested)
            return 1;
        tid = waitpid(mode == DRAIN_INITIAL_STOP ? root : -1, &status, __WALL | WNOHANG);
        if (tid == 0) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
            nanosleep(&pause, NULL);
            continue;
        }
        if (tid < 0 && errno == EINTR)
            continue;
        if (tid < 0 && errno == ECHILD) {
            collector->wait_echild = 1;
            if (mode == DRAIN_INITIAL_STOP)
                return -1;
            if (mode == DRAIN_CLEANUP)
                return containment_closed(collector) ? 0 : -1;
            return terminal_failure ? -1 : lifecycle_complete(collector) ? 0 : -1;
        }
        if (tid < 0)
            return -1;
        if (mode == DRAIN_INITIAL_STOP) {
            if (initial_status == NULL)
                return -1;
            *initial_status = status;
            return 0;
        }
        if (collector->helper < 0 && collector->helper_candidate > 0 &&
            tid == collector->helper_candidate)
            collector->helper = collector->helper_candidate;
        if (collector->helper >= 0 && tid == collector->helper) {
            collector->helper_reaped = 1;
            collector->helper_status = status;
            continue;
        }
        if (mode == DRAIN_NORMAL && WIFSTOPPED(status)) {
            struct task *task = find_any_task(collector, tid);
            if (task != NULL && task->terminal_wait_pending) {
                struct observation observation;
                struct transition_actions actions;
                memset(&observation, 0, sizeof(observation));
                observation.kind = OBS_CLEANUP_STOP;
                observation.generation = task->generation;
                observation.event_kind =
                    (uint16_t)((unsigned int)((unsigned int)status >> 16));
                if (transition(collector, &observation, &actions) != 0)
                    return -1;
                memset(&actions, 0, sizeof(actions));
                actions.contain_group = 1;
                if (execute_actions(collector, root, 0, &actions) != 0)
                    return -1;
                memset(&actions, 0, sizeof(actions));
                actions.resume = 1;
                actions.resume_cont = 1;
                if (execute_actions(collector, tid, task->generation, &actions) != 0)
                    return -1;
                terminal_failure = 1;
                mode = DRAIN_CLEANUP;
                if (begin_cleanup(collector, root) != 0)
                    return -1;
                continue;
            }
        }
        if (mode == DRAIN_CLEANUP) {
            struct task *task = find_any_task(collector, tid);
            if (WIFSTOPPED(status)) {
                struct observation observation;
                struct transition_actions actions;
                unsigned int event = (unsigned int)((unsigned int)status >> 16);
                memset(&observation, 0, sizeof(observation));
                if (task != NULL) {
                    observation.kind = OBS_CLEANUP_STOP;
                    observation.generation = task->generation;
                    observation.event_kind = (uint16_t)event;
                } else {
                    observation.kind = OBS_CLEANUP_UNKNOWN_STOP;
                    observation.event_kind = (uint16_t)event;
                    observation.tid = tid;
                }
                if (transition(collector, &observation, &actions) != 0)
                    return -1;
                memset(&actions, 0, sizeof(actions));
                actions.contain_group = 1;
                if (execute_actions(collector, root, 0, &actions) != 0)
                    return -1;
                memset(&actions, 0, sizeof(actions));
                if (task == NULL) {
                    int pending = pending_stop_index(collector, tid);
                    if (pending < 0)
                        return -1;
                    if (collector->pending_stops[(size_t)pending].cleanup_resumed)
                        continue;
                    collector->pending_stops[(size_t)pending].cleanup_resumed = 1;
                }
                actions.resume = 1;
                actions.resume_cont = 1;
                if (execute_actions(collector, tid, task == NULL ? 0 : task->generation,
                                    &actions) != 0)
                    return -1;
                continue;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                struct observation observation;
                struct transition_actions actions;
                memset(&observation, 0, sizeof(observation));
                if (task != NULL) {
                    observation.kind = OBS_CLEANUP_WIF;
                    observation.generation = task->generation;
                    observation.status = (uint32_t)status;
                    if (transition(collector, &observation, &actions) != 0)
                        return -1;
                } else {
                    int pending = pending_stop_index(collector, tid);
                    int event_first = 0;
                    for (size_t i = 0; i != collector->creation_count; ++i) {
                        const struct creation *creation = &collector->creations[i];
                        if (creation->event && !creation->joined && creation->child_tid == tid) {
                            event_first = 1;
                            break;
                        }
                    }
                    if (pending >= 0 || event_first) {
                        observation.kind = OBS_CLEANUP_UNKNOWN_WIF;
                        observation.tid = tid;
                        observation.status = (uint32_t)status;
                        if (transition(collector, &observation, &actions) != 0)
                            return -1;
                    } else if (collector->helper_expected && collector->helper < 0 &&
                               !collector->helper_reaped &&
                               (WIFEXITED(status) || WIFSIGNALED(status))) {
                        collector->helper_reaped = 1;
                        collector->helper_status = status;
                    } else {
                        return -1;
                    }
                }
                continue;
            }
            return -1;
        }
        {
            int result = handle_wait(collector, tid, status);
            if (result == -2)
                return -2;
            if (result == -3)
                continue;
            if (result != 0)
                return -1;
            if (cleanup_signal_for_case(collector->case_name) != 0 && stop_requested)
                return 1;
            if (WIFSTOPPED(status)) {
                struct task *task = find_any_task(collector, tid);
                unsigned int event = (unsigned int)((unsigned int)status >> 16);
                struct transition_actions actions;
                if (task == NULL)
                    return -1;
                if (event != 0) {
                    memset(&actions, 0, sizeof(actions));
                    actions.resume = 1;
                    actions.resume_cont = event == PTRACE_EVENT_EXIT;
                    if (execute_actions(collector, tid, task->generation, &actions) != 0)
                        return -1;
                }
            }
        }
    }
}

static int finish_cleanup_signal(struct collector *collector)
{
    int expected_signal = cleanup_signal_for_case(collector->case_name);
    if (expected_signal == 0 || !collector->cleanup_exec_triggered ||
        received_signal != expected_signal || !collector->helper_go_released ||
        collector->helper < 0 || collector->helper_ack_fd < 0)
        return -1;
    if (wait_ack(collector->helper_ack_fd, 1, collector->deadline) != 0 ||
        close(collector->helper_ack_fd) != 0)
        return -1;
    collector->helper_ack_fd = -1;
    collector->helper_ack = 1;
    return 0;
}

static int handle_wait(struct collector *collector, pid_t tid, int status)
{
    struct task *task = find_any_task(collector, tid);
    unsigned int event;
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        struct observation observation;
        struct transition_actions actions;
        task = find_any_task(collector, tid);
        if (task == NULL)
            return -1;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_FINAL_WIF;
        observation.generation = task->generation;
        observation.status = (uint32_t)status;
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        return execute_actions(collector, tid, task->generation, &actions) == 0 ? 0 : -1;
    }
    if (!WIFSTOPPED(status))
        return -1;
    event = (unsigned int)((unsigned int)status >> 16);
    if (task == NULL && event == PTRACE_EVENT_STOP && WSTOPSIG(status) == SIGTRAP) {
        struct observation observation;
        struct transition_actions actions;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_CHILD_STOP;
        observation.tid = tid;
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        if (execute_actions(collector, tid, 0, &actions) != 0)
            return -1;
        return actions.hold ? -3 : 0;
    }
    if (task == NULL)
        return -1;
    if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
        struct p11_ptrace_syscall_info info;
        long size = ptrace(PTRACE_GET_SYSCALL_INFO, tid, sizeof(info), &info);
        int result;
        if (size < 0 && errno == ESRCH && mark_terminal_pending(collector, task->generation) == 0)
            return -3;
        if (size < (long)sizeof(info.op) || info.arch != AUDIT_ARCH_X86_64 ||
            (info.op != PTRACE_SYSCALL_INFO_ENTRY && info.op != PTRACE_SYSCALL_INFO_EXIT))
            return -1;
        result = process_syscall(collector, task, info.op == PTRACE_SYSCALL_INFO_ENTRY, &info);
        if (result != 0)
            return result;
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == SYS_fcntl &&
            strcmp(collector->case_name, "kernel-restart-reject") == 0 &&
            task->generation == 1 && task->tid == collector->root &&
            task->fcntl_command == F_SETLKW && collector->restart_state == 0) {
            struct transition_actions actions;
            memset(&actions, 0, sizeof(actions));
            actions.resume = 1;
            actions.deliver_signal = SIGUSR2;
            actions.signal_tid = tid;
            if (execute_actions(collector, tid, task->generation, &actions) != 0)
                return -1;
            if (actions.hold)
                return -3;
            collector->restart_state = 1;
            return 0;
        }
        if (info.op == PTRACE_SYSCALL_INFO_EXIT &&
            strcmp(collector->case_name, "kernel-group-stop-reject") == 0 &&
            task->generation == 1 && task->tid == collector->root &&
            task->fcntl_command == F_GETFD && info.exit.rval == 0 &&
            collector->group_stop_state == 0) {
            struct observation observation;
            struct transition_actions actions;
            memset(&observation, 0, sizeof(observation));
            observation.kind = OBS_SIGNAL_DELIVERY;
            observation.generation = task->generation;
            observation.status = SIGSTOP;
            observation.signal_phase = SIGNAL_PHASE_GROUP_ARM;
            if (transition(collector, &observation, &actions) != 0)
                return -1;
            if (execute_actions(collector, tid, task->generation, &actions) != 0)
                return -1;
            return actions.hold ? -3 : 0;
        }
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == SYS_fcntl &&
            expected_signal_for_case(collector) != 0 &&
            collector->signal_state == 0) {
            struct observation observation;
            struct transition_actions actions;
            int signal_number = expected_signal_for_case(collector);
            memset(&observation, 0, sizeof(observation));
            observation.kind = OBS_SIGNAL_DELIVERY;
            observation.generation = task->generation;
            observation.status = (uint32_t)signal_number;
            observation.signal_phase = SIGNAL_PHASE_ARM;
            if (transition(collector, &observation, &actions) != 0)
                return -1;
            if (execute_actions(collector, tid, task->generation, &actions) != 0)
                return -1;
            return actions.hold ? -3 : 0;
        }
        {
            struct transition_actions actions;
            memset(&actions, 0, sizeof(actions));
            actions.resume = 1;
            if (execute_actions(collector, tid, task->generation, &actions) != 0)
                return -1;
            return actions.hold ? -3 : 0;
        }
    }
    if (event == PTRACE_EVENT_STOP) {
        if (is_stopping_signal(WSTOPSIG(status))) {
            struct observation observation;
            struct transition_actions actions;
            memset(&observation, 0, sizeof(observation));
            observation.kind = OBS_SIGNAL_DELIVERY;
            observation.generation = task->generation;
            observation.status = (uint32_t)WSTOPSIG(status);
            observation.signal_phase = SIGNAL_PHASE_EVENT_STOP;
            return transition(collector, &observation, &actions);
        }
        return -1;
    }
    if (event != 0)
        return process_event(collector, task, event);
    if (WSTOPSIG(status) == SIGKILL) {
        struct observation observation;
        struct transition_actions actions;
        struct creation *creation = creation_for_child(collector, task->generation);
        if (creation == NULL || !creation->collector_kill)
            return -1;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_SIGNAL_DELIVERY;
        observation.generation = task->generation;
        observation.status = SIGKILL;
        observation.signal_phase = SIGNAL_PHASE_CLEANUP;
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        if (execute_actions(collector, tid, task->generation, &actions) != 0)
            return -1;
        return 0;
    }
    if (WSTOPSIG(status) > 0 && WSTOPSIG(status) < NSIG &&
        WSTOPSIG(status) != SIGKILL && !is_stopping_signal(WSTOPSIG(status))) {
        struct observation observation;
        struct transition_actions actions;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_SIGNAL_DELIVERY;
        observation.generation = task->generation;
        observation.status = (uint32_t)WSTOPSIG(status);
        observation.signal_phase = SIGNAL_PHASE_ORDINARY;
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        return execute_actions(collector, tid, task->generation, &actions) == 0 ? 0 : -1;
    }
    if (is_stopping_signal(WSTOPSIG(status))) {
        struct observation observation;
        struct transition_actions actions;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_SIGNAL_DELIVERY;
        observation.generation = task->generation;
        observation.status = (uint32_t)WSTOPSIG(status);
        observation.signal_phase = SIGNAL_PHASE_STOPPING;
        {
            siginfo_t signal_info;
            if (ptrace(PTRACE_GETSIGINFO, tid, 0, &signal_info) != 0) {
                if (errno == EINVAL) {
                    observation.signal_info = SIGNAL_INFO_EINVAL;
                    return transition(collector, &observation, &actions);
                }
                if (errno == ESRCH && mark_terminal_pending(collector, task->generation) == 0)
                    return -3;
                return -1;
            }
            if (signal_info.si_signo != WSTOPSIG(status))
                return -1;
            observation.signal_info = SIGNAL_INFO_SUCCESS;
        }
        if (transition(collector, &observation, &actions) != 0)
            return -1;
        return execute_actions(collector, tid, task->generation, &actions) == 0 ? 0 : -1;
    }
    return -1;
}

static int child_ready(int ready_read, int ready_write, int release_read, int release_write,
                       int output_fd, int watchdog_fd, const char *case_name,
                       int helper_go_read,
                       int helper_go_write, int helper_ack_read, int helper_ack_write,
                       pid_t *helper_pid, pid_t collector_pid, int helper_signal)
{
    unsigned char marker = 1;
    pid_t root_pid;
    pid_t helper = -1;
    root_pid = getpid();
    close(ready_read);
    close(release_write);
    close(output_fd);
    close(watchdog_fd);
    if (helper_go_write >= 0)
        close(helper_go_write);
    if (helper_ack_read >= 0)
        close(helper_ack_read);
    if (setpgid(0, 0) != 0 || getpgid(0) != root_pid)
        _exit(111);
    if (helper_signal != 0) {
        pid_t expected_helper_parent = getpid();
        helper = fork();
        if (helper < 0)
            _exit(111);
        if (helper == 0) {
            cleanup_helper_child(expected_helper_parent, root_pid, collector_pid, helper_go_read,
                                 helper_go_write, helper_ack_read, helper_ack_write, ready_write,
                                 release_read, helper_signal);
            _exit(123);
        }
        if (helper_go_read >= 0)
            close(helper_go_read);
        if (helper_ack_write >= 0)
            close(helper_ack_write);
        if (helper_pid == NULL)
            _exit(111);
        *helper_pid = helper;
        __sync_synchronize();
    }
    if (strcmp(case_name, "kernel-signal-ignored") == 0)
        (void)signal(SIGUSR1, SIG_IGN);
    if (probe_policy() != 0) {
        _exit(112);
    }
    if (write(ready_write, &marker, 1) != 1) {
        _exit(113);
    }
    close(ready_write);
    if (read(release_read, &marker, 1) != 1)
        _exit(114);
    close(release_read);
    execl("/proc/self/exe", "/proc/self/exe", "internal-workload", case_name,
          (char *)NULL);
    _exit(116);
}

static void child_fcntl_and_exit(int status)
{
    (void)tracee_getfd();
    _exit(status);
}

static void empty_restart_handler(int signal_number)
{
    (void)signal_number;
}

static int run_restart_workload(void)
{
    int lock_fd = -1;
    int ready[2] = {-1, -1};
    struct flock lock;
    struct sigaction action;
    pid_t holder;
    unsigned char marker = 0xa5;
    unsigned char received = 0;
    ssize_t count;
    pid_t expected_holder_parent;

    lock_fd = (int)syscall(SYS_memfd_create, "p11scope-s9-lock", MFD_CLOEXEC);
    if (lock_fd < 0 || ftruncate(lock_fd, 1) != 0 || pipe2(ready, O_CLOEXEC) != 0)
        _exit(2);
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 1;
    expected_holder_parent = getpid();
    holder = fork();
    if (holder < 0)
        _exit(2);
    if (holder == 0) {
        if (arm_pdeath(expected_holder_parent) != 0 || close(ready[0]) != 0 ||
            fcntl(lock_fd, F_SETLK, &lock) != 0 ||
            write(ready[1], &marker, 1) != 1 || close(ready[1]) != 0)
            _exit(2);
        for (;;)
            (void)syscall(SYS_pause);
    }
    close(ready[1]);
    do {
        count = read(ready[0], &received, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 1 || received != marker)
        _exit(2);
    do {
        count = read(ready[0], &received, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 0 || close(ready[0]) != 0)
        _exit(2);
    memset(&action, 0, sizeof(action));
    action.sa_handler = empty_restart_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR2, &action, NULL) != 0)
        _exit(2);
    (void)fcntl(lock_fd, F_SETLKW, &lock);
    _exit(0);
}

static int run_thread_child(void *argument)
{
    if (arm_pdeath(*(const pid_t *)argument) != 0)
        _exit(2);
    execl("/proc/self/exe", "/proc/self/exe", "internal-workload",
          "kernel-signal-ignored", (char *)NULL);
    _exit(0);
}

static int internal_workload(const char *case_name)
{
    if (strcmp(case_name, "kernel-bootstrap") == 0)
        _exit(0);
    if (strcmp(case_name, "kernel-fork") == 0) {
        sigset_t blocked;
        pid_t child;
        pid_t waited;
        int status;
        pid_t expected_parent = getpid();
        if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGCHLD) != 0 ||
            sigprocmask(SIG_BLOCK, &blocked, NULL) != 0)
            _exit(2);
        child = fork();
        if (child == 0) {
            if (arm_pdeath(expected_parent) != 0)
                _exit(2);
            child_fcntl_and_exit(7);
        }
        if (child < 0)
            _exit(2);
        (void)tracee_getfd();
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 7)
            _exit(3);
        _exit(0);
    }
    if (strcmp(case_name, "kernel-clone") == 0) {
        pid_t child;
        pid_t waited;
        int status;
        pid_t expected_parent = getpid();
        child = (pid_t)syscall(SYS_clone, 0, 0, 0, 0, 0);
        if (child == 0) {
            if (arm_pdeath(expected_parent) != 0)
                _exit(2);
            child_fcntl_and_exit(0);
        }
        if (child < 0)
            _exit(2);
        (void)tracee_getfd();
        do {
            waited = waitpid(child, &status, __WCLONE);
        } while (waited < 0 && errno == EINTR);
        if (waited != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL)
            _exit(3);
        _exit(0);
    }
    if (strcmp(case_name, "kernel-vfork") == 0) {
        sigset_t blocked;
        pid_t child;
        pid_t waited;
        int status;
        char vfork_exe[] = "/proc/self/exe";
        char vfork_workload[] = "internal-workload";
        char vfork_case[] = "kernel-signal-ignored";
        char *vfork_argv[] = {vfork_exe, vfork_workload, vfork_case, NULL};
        char *vfork_envp[] = {NULL};
        const char *vfork_exe_path = vfork_exe;
        char **vfork_argv_ptr = vfork_argv;
        char **vfork_envp_ptr = vfork_envp;
        long expected_parent = (long)getpid();
        if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGCHLD) != 0 ||
            sigprocmask(SIG_BLOCK, &blocked, NULL) != 0)
            _exit(2);
        child = vfork();
        if (child == 0) {
            __asm__ volatile(
                "mov %[prctl_nr], %%eax\n\t"
                "xor %%r10d, %%r10d\n\t"
                "xor %%r8d, %%r8d\n\t"
                "xor %%r9d, %%r9d\n\t"
                "mov %[pdeathsig], %%edi\n\t"
                "mov %[sigkill], %%esi\n\t"
                "xor %%edx, %%edx\n\t"
                "syscall\n\t"
                "test %%rax, %%rax\n\t"
                "jnz 1f\n\t"
                "cmpq $1, %[expected_parent]\n\t"
                "jle 1f\n\t"
                "mov %[getppid_nr], %%eax\n\t"
                "syscall\n\t"
                "cmpq %[expected_parent], %%rax\n\t"
                "jne 1f\n\t"
                "mov %[execve_nr], %%eax\n\t"
                "mov %[exe_path], %%rdi\n\t"
                "mov %[argv], %%rsi\n\t"
                "mov %[envp], %%rdx\n\t"
                "syscall\n\t"
                "1:\n\t"
                "mov %[exit_nr], %%eax\n\t"
                "mov $2, %%edi\n\t"
                "syscall\n\t"
                "ud2\n\t"
                :
                : [prctl_nr] "i"((long)SYS_prctl),
                  [pdeathsig] "i"((long)PR_SET_PDEATHSIG),
                  [sigkill] "i"((long)SIGKILL),
                  [getppid_nr] "i"((long)SYS_getppid),
                  [execve_nr] "i"((long)SYS_execve),
                  [exit_nr] "i"((long)SYS_exit),
                  [expected_parent] "m"(expected_parent),
                  [exe_path] "m"(vfork_exe_path),
                  [argv] "m"(vfork_argv_ptr),
                  [envp] "m"(vfork_envp_ptr)
                : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11", "cc",
                  "memory");
            __builtin_unreachable();
        }
        if (child < 0)
            _exit(2);
        (void)tracee_getfd();
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            _exit(3);
        _exit(0);
    }
    if (strcmp(case_name, "kernel-nonleader-exec") == 0) {
        char *stack;
        pid_t child;
        pid_t expected_parent = getppid();
        stack = mmap(NULL, 1U << 20, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (stack == MAP_FAILED)
            _exit(2);
        child = clone(run_thread_child, stack + (1U << 20),
                      CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
                      &expected_parent);
        if (child < 0)
            _exit(2);
        for (;;) {
            volatile unsigned long spin = 0;
            ++spin;
            (void)spin;
        }
    }
    if (strcmp(case_name, "kernel-signal-ignored") == 0) {
        int pdeath_signal = 0;
        if (prctl(PR_GET_PDEATHSIG, &pdeath_signal) != 0 || pdeath_signal != SIGKILL)
            _exit(2);
        (void)tracee_getfd();
        _exit(0);
    }
    if (strcmp(case_name, "kernel-signal-caught") == 0) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = tracee_caught_signal;
        action.sa_flags = SA_RESTART;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR2, &action, NULL) != 0)
            _exit(2);
        (void)tracee_getfd();
        _exit(0);
    }
    if (strcmp(case_name, "kernel-restart-reject") == 0) {
        return run_restart_workload();
    }
    if (strcmp(case_name, "kernel-group-stop-reject") == 0) {
        (void)tracee_getfd();
        for (;;)
            (void)syscall(SYS_pause);
    }
    if (strcmp(case_name, "kernel-cleanup-failure") == 0) {
        _Atomic unsigned int *gate;
        int gate_pipe[2] = {-1, -1};
        pid_t child;
        pid_t expected_parent = getpid();
        unsigned char marker = 1;
        unsigned char received = 0;
        ssize_t count;
        gate = mmap(NULL, sizeof(*gate), PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (gate == MAP_FAILED || pipe2(gate_pipe, O_CLOEXEC) != 0)
            _exit(2);
        atomic_init(gate, 0U);
        child = fork();
        if (child < 0)
            _exit(2);
        if (child == 0) {
            if (arm_pdeath(expected_parent) != 0)
                _exit(2);
            if (close(gate_pipe[0]) != 0 || write(gate_pipe[1], &marker, 1) != 1 ||
                close(gate_pipe[1]) != 0)
                _exit(2);
            atomic_store_explicit(gate, 1U, memory_order_release);
            for (;;)
                atomic_signal_fence(memory_order_seq_cst);
        }
        if (close(gate_pipe[1]) != 0)
            _exit(2);
        do {
            count = read(gate_pipe[0], &received, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1 || received != marker)
            _exit(2);
        do {
            count = read(gate_pipe[0], &received, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 0)
            _exit(2);
        while (atomic_load_explicit(gate, memory_order_acquire) == 0U)
            atomic_signal_fence(memory_order_seq_cst);
        if (close(gate_pipe[0]) != 0 || tracee_getfd() < 0)
            _exit(2);
        _exit(2);
    }
    if (strncmp(case_name, "kernel-cleanup", 14) == 0) {
        for (;;)
            (void)syscall(SYS_pause);
    }
    return 77;
}

static int finish_tasks(struct collector *collector)
{
    for (size_t i = 0; i != collector->task_count; ++i) {
        struct task *task = &collector->tasks[i];
        if (task->superseded)
            continue;
        if (!task->exited || !task->wif || task->terminal_wait_pending || task->syscall_entry ||
            task->creation != 0 || task->fcntl != 0)
            return -1;
    }
    return 0;
}

static int containment_closed(const struct collector *collector)
{
    if (!collector->wait_echild || collector->pending_stop_count != 0 ||
        (collector->helper >= 0 && !collector->helper_reaped))
        return 0;
    for (size_t i = 0; i != collector->task_count; ++i) {
        const struct task *task = &collector->tasks[i];
        if (task->superseded)
            continue;
        if (task->live || !task->exited || !task->wif || task->terminal_wait_pending)
            return 0;
    }
    return 1;
}

static int lifecycle_complete(const struct collector *collector)
{
    if (!containment_closed(collector))
        return 0;
    for (size_t i = 0; i != collector->task_count; ++i) {
        const struct task *task = &collector->tasks[i];
        if (task->superseded)
            continue;
        if (task->syscall_entry || task->creation != 0 || task->fcntl != 0)
            return 0;
    }
    for (size_t i = 0; i != collector->creation_count; ++i) {
        const struct creation *creation = &collector->creations[i];
        if (!creation->result_seen || creation->cleanup_cancelled || creation->child_stop ||
            (creation->joined && creation->child_generation == 0) ||
            (creation->event && !creation->joined))
            return 0;
    }
    return 1;
}

static int feed_observation(struct collector *collector, struct observation observation)
{
    struct transition_actions actions;
    return transition(collector, &observation, &actions);
}

static void negative_init(struct collector *collector, unsigned char *data,
                          const char *case_name)
{
    memset(collector, 0, sizeof(*collector));
    memset(data, 0, RECORD_SIZE * 32U);
    collector->case_name = case_name;
    collector->root = 100;
    collector->helper = -1;
    collector->journal.data = data;
    collector->next_generation = 1;
    collector->next_creation = 1;
    collector->next_invocation = 1;
    collector->next_group = 1;
}

static int negative_seed(struct collector *collector)
{
    if (feed_observation(collector, (struct observation){.kind = OBS_HEADER}) != 0 ||
        feed_observation(collector, (struct observation){.kind = OBS_ROOT}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_EXEC, .generation = 1, .exec_class = 1}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 0}) != 0)
        return -1;
    return collector->journal.count == 3 && collector->header_seen && collector->root_seen &&
                   collector->saw_exec
               ? 0
               : -1;
}

static int negative_vfork_seed(struct collector *collector)
{
    if (negative_seed(collector) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 2}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 2, .tid = 20}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}) != 0)
        return -1;
    return collector->journal.count == 6 && collector->tasks[0].creation == 1 &&
                   collector->creations[0].joined && collector->creations[0].done == 0
               ? 0
               : -1;
}

static int negative_reject(struct collector *collector, struct observation observation,
                           int expected, size_t count)
{
    return feed_observation(collector, observation) == expected &&
                   collector->journal.count == count
               ? 0
               : -1;
}

static int negative_reject_atomic(struct collector *collector,
                                  struct observation observation, int expected, size_t count)
{
    unsigned char before[RECORD_SIZE * 32U];
    memcpy(before, collector->journal.data, sizeof(before));
    if (negative_reject(collector, observation, expected, count) != 0)
        return -1;
    return memcmp(before, collector->journal.data, sizeof(before)) == 0 ? 0 : -1;
}

static int transition_reject_atomic(struct collector *collector,
                                    struct observation observation, int expected)
{
    unsigned char collector_before[sizeof(*collector)];
    unsigned char journal_before[RECORD_SIZE * 32U];
    struct transition_actions actions;
    memcpy(collector_before, collector, sizeof(collector_before));
    memcpy(journal_before, collector->journal.data, sizeof(journal_before));
    if (transition(collector, &observation, &actions) != expected ||
        memcmp(collector_before, collector, sizeof(collector_before)) != 0 ||
        memcmp(journal_before, collector->journal.data, sizeof(journal_before)) != 0)
        return -1;
    return 0;
}

static int pseudo_reject_atomic(struct collector *collector,
                                struct observation observation, int expected_observed)
{
    unsigned char collector_before[sizeof(*collector)];
    unsigned char journal_before[RECORD_SIZE * 32U];
    struct transition_actions actions;
    memcpy(collector_before, collector, sizeof(collector_before));
    memcpy(journal_before, collector->journal.data, sizeof(journal_before));
    if (transition(collector, &observation, &actions) != -2 || !actions.reject)
        return -1;
    if (expected_observed) {
        int observed = collector->restart_observed;
        if (observed != 1)
            return -1;
        collector->restart_observed = 0;
        if (memcmp(collector_before, collector, sizeof(collector_before)) != 0) {
            collector->restart_observed = observed;
            return -1;
        }
        collector->restart_observed = observed;
    } else if (memcmp(collector_before, collector, sizeof(collector_before)) != 0) {
        return -1;
    }
    if (memcmp(journal_before, collector->journal.data, sizeof(journal_before)) != 0)
        return -1;
    return 0;
}

static int signal_reject_atomic(struct collector *collector,
                                struct observation observation, int expected)
{
    unsigned char collector_before[sizeof(*collector)];
    unsigned char journal_before[RECORD_SIZE * 32U];
    struct transition_actions actions;
    memcpy(collector_before, collector, sizeof(collector_before));
    memcpy(journal_before, collector->journal.data, sizeof(journal_before));
    if (transition(collector, &observation, &actions) != expected || !actions.reject ||
        actions.resume || actions.resume_signal != 0 || actions.deliver_signal ||
        actions.signal_before_resume || actions.signal_tid != 0 || actions.action_tid != 0 ||
        memcmp(collector_before, collector, sizeof(collector_before)) != 0 ||
        memcmp(journal_before, collector->journal.data, sizeof(journal_before)) != 0)
        return -1;
    return 0;
}

static int ordinary_signal_checks(int signal_number)
{
    unsigned char data[RECORD_SIZE * 32U];
    struct collector collector;
    struct transition_actions actions;
    unsigned char expected[4];
    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        signal_reject_atomic(&collector, (struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = 0,
            .signal_phase = SIGNAL_PHASE_ARM}, -1) != 0)
        return -1;
    memset(&actions, 0, sizeof(actions));
    if (transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = (uint32_t)signal_number,
            .signal_phase = SIGNAL_PHASE_ORDINARY}, &actions) != 0 || !actions.resume ||
        actions.resume_signal != signal_number || actions.deliver_signal ||
        actions.signal_before_resume || collector.signal_state != 0 ||
        collector.journal.count != 4)
        return -1;
    put32(expected, (uint32_t)signal_number);
    if (memcmp(collector.journal.data + 3 * RECORD_SIZE + 32, expected, sizeof(expected)) != 0)
        return -1;
    memset(&actions, 0, sizeof(actions));
    if (transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1,
            .status = (uint32_t)signal_number, .signal_phase = SIGNAL_PHASE_ORDINARY},
            &actions) != 0 || collector.signal_state != 0 || !actions.resume ||
        actions.resume_signal != signal_number || actions.deliver_signal ||
        actions.signal_before_resume || collector.journal.count != 5)
        return -1;
    memset(&actions, 0, sizeof(actions));
    if (transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = SIGWINCH,
            .signal_phase = SIGNAL_PHASE_ORDINARY}, &actions) != 0 || !actions.resume ||
        actions.resume_signal != SIGWINCH || collector.journal.count != 6)
        return -1;
    negative_init(&collector, data,
                  signal_number == SIGUSR1 ? "kernel-signal-ignored" : "kernel-signal-caught");
    if (negative_seed(&collector) != 0)
        return -1;
    memset(&actions, 0, sizeof(actions));
    if (transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = (uint32_t)signal_number,
            .signal_phase = SIGNAL_PHASE_ORDINARY}, &actions) != 0 || !actions.resume ||
        actions.resume_signal != signal_number || collector.signal_state != 0 ||
        collector.journal.count != 4)
        return -1;
    negative_init(&collector, data,
                  signal_number == SIGUSR1 ? "kernel-signal-ignored" : "kernel-signal-caught");
    if (negative_seed(&collector) != 0 ||
        signal_reject_atomic(&collector, (struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1,
            .status = (uint32_t)(signal_number == SIGUSR1 ? SIGUSR2 : SIGUSR1),
            .signal_phase = SIGNAL_PHASE_ARM}, -1) != 0)
        return -1;
    memset(&actions, 0, sizeof(actions));
    if (transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = (uint32_t)signal_number,
            .signal_phase = SIGNAL_PHASE_ARM}, &actions) != 0 || collector.signal_state != 1 ||
        !actions.resume || actions.deliver_signal != signal_number ||
        !actions.signal_before_resume || actions.resume_signal != 0 ||
        actions.signal_tid != collector.root)
        return -1;
    memset(&actions, 0, sizeof(actions));
    if (transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = (uint32_t)signal_number,
            .signal_phase = SIGNAL_PHASE_ORDINARY}, &actions) != 0 || collector.signal_state != 2 ||
        !actions.resume || actions.resume_signal != signal_number || collector.journal.count != 4)
        return -1;
    return 0;
}

static int stopping_signal_checks(void)
{
    static const int stopping_signals[] = {SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU};
    unsigned char data[RECORD_SIZE * 32U];
    struct collector collector;
    struct transition_actions actions;
    unsigned char expected[4];
    for (size_t i = 0; i != sizeof(stopping_signals) / sizeof(stopping_signals[0]); ++i) {
        negative_init(&collector, data, "sim-negative");
        if (negative_seed(&collector) != 0 ||
            signal_reject_atomic(&collector, (struct observation){
                .kind = OBS_SIGNAL_DELIVERY, .generation = 1,
                .status = (uint32_t)stopping_signals[i],
                .signal_phase = SIGNAL_PHASE_EVENT_STOP}, -2) != 0)
            return -1;
    }
    for (size_t i = 0; i != sizeof(stopping_signals) / sizeof(stopping_signals[0]); ++i) {
        negative_init(&collector, data, "sim-negative");
        memset(&actions, 0, sizeof(actions));
        if (negative_seed(&collector) != 0 ||
            transition(&collector, &(struct observation){
                .kind = OBS_SIGNAL_DELIVERY, .generation = 1,
                .status = (uint32_t)stopping_signals[i], .signal_phase = SIGNAL_PHASE_STOPPING,
                .signal_info = SIGNAL_INFO_SUCCESS}, &actions) != 0 || !actions.resume ||
            actions.resume_signal != stopping_signals[i] || actions.deliver_signal ||
            collector.journal.count != 4)
            return -1;
        put32(expected, (uint32_t)stopping_signals[i]);
        if (memcmp(collector.journal.data + 3 * RECORD_SIZE + 32, expected, sizeof(expected)) != 0)
            return -1;
    }
    for (size_t i = 0; i != sizeof(stopping_signals) / sizeof(stopping_signals[0]); ++i) {
        negative_init(&collector, data, "sim-negative");
        if (negative_seed(&collector) != 0 ||
            signal_reject_atomic(&collector, (struct observation){
                .kind = OBS_SIGNAL_DELIVERY, .generation = 1,
                .status = (uint32_t)stopping_signals[i], .signal_phase = SIGNAL_PHASE_STOPPING,
                .signal_info = SIGNAL_INFO_EINVAL}, -2) != 0)
            return -1;
    }
    negative_init(&collector, data, "sim-negative");
    collector.group_stop_state = 2;
    if (negative_seed(&collector) != 0)
        return -1;
    {
        unsigned char before[RECORD_SIZE * 32U];
        memcpy(before, collector.journal.data, sizeof(before));
        memset(&actions, 0, sizeof(actions));
        if (transition(&collector, &(struct observation){
                .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = SIGSTOP,
                .signal_phase = SIGNAL_PHASE_STOPPING, .signal_info = SIGNAL_INFO_EINVAL},
                &actions) != -2 || !actions.reject || actions.resume ||
            collector.group_stop_state != 3 || !collector.group_stop_observed ||
            collector.journal.count != 3 || memcmp(before, collector.journal.data, sizeof(before)) != 0)
            return -1;
    }
    negative_init(&collector, data, "sim-negative");
    collector.group_stop_state = 1;
    memset(&actions, 0, sizeof(actions));
    if (negative_seed(&collector) != 0 ||
        transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = SIGSTOP,
            .signal_phase = SIGNAL_PHASE_STOPPING, .signal_info = SIGNAL_INFO_SUCCESS}, &actions) != 0 ||
        collector.group_stop_state != 2 || !actions.resume || actions.resume_signal != SIGSTOP ||
        actions.deliver_signal || collector.journal.count != 4)
        return -1;
    negative_init(&collector, data, "sim-negative");
    collector.group_stop_state = 2;
    if (negative_seed(&collector) != 0 ||
        transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = SIGSTOP,
            .signal_phase = SIGNAL_PHASE_EVENT_STOP}, &actions) != -2 || !actions.reject ||
        actions.resume || collector.group_stop_state != 3 || !collector.group_stop_observed)
        return -1;
    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        signal_reject_atomic(&collector, (struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = SIGTRAP,
            .signal_phase = SIGNAL_PHASE_EVENT_STOP}, -1) != 0)
        return -1;
    negative_init(&collector, data, "sim-negative");
    memset(&actions, 0, sizeof(actions));
    if (negative_seed(&collector) != 0 ||
        transition(&collector, &(struct observation){
            .kind = OBS_SIGNAL_DELIVERY, .generation = 1, .status = SIGTSTP,
            .signal_phase = SIGNAL_PHASE_STOPPING, .signal_info = SIGNAL_INFO_ESRCH}, &actions) != -3 ||
        !collector.tasks[0].terminal_wait_pending || actions.resume || actions.reject)
        return -1;
    return 0;
}

static int fcntl_binding_checks(void)
{
    unsigned char data[RECORD_SIZE * 32U];
    struct collector collector;
    {
        static const uint64_t sentinels[6] = {
            0x1111111111111111ULL, 0x2222222222222222ULL,
            0x3333333333333333ULL, 0x4444444444444444ULL,
            0x5555555555555555ULL, 0x6666666666666666ULL
        };
        struct p11_ptrace_syscall_info info;
        unsigned char expected[48];
        memset(&info, 0, sizeof(info));
        info.op = PTRACE_SYSCALL_INFO_ENTRY;
        info.entry.nr = SYS_fcntl;
        for (size_t i = 0; i != 6; ++i) {
            info.entry.args[i] = sentinels[i];
            put64(expected + 8U * i, sentinels[i]);
        }
        negative_init(&collector, data, "sim-negative");
        if (negative_seed(&collector) != 0 ||
            process_syscall(&collector, &collector.tasks[0], 1, &info) != 0 ||
            collector.journal.count != 4 ||
            memcmp(collector.journal.data + 3 * RECORD_SIZE + 40, expected,
                   sizeof(expected)) != 0)
            return -1;
    }
    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        transition_reject_atomic(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .parent = 0,
            .syscall_kind = 5, .invocation = 1,
            .arguments = {STDERR_FILENO, F_GETFD, 0}}, -1) != 0)
        return -1;
    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        transition_reject_atomic(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .parent = SYS_fcntl,
            .syscall_kind = 0}, -1) != 0)
        return -1;
    return 0;
}

static int restart_context_matrix_checks(void)
{
    unsigned char data[RECORD_SIZE * 32U];
    struct collector baseline;
    negative_init(&baseline, data, "kernel-restart-reject");
    baseline.restart_state = 1;
    if (negative_seed(&baseline) != 0 ||
        feed_observation(&baseline, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .parent = SYS_fcntl,
            .syscall_kind = 5, .invocation = 1,
            .arguments = {STDERR_FILENO, F_SETLKW, 0x1234}}) != 0)
        return -1;
#define REJECT_RESTART_MUTATION(statement)                                           \
    do {                                                                             \
        struct collector mutated = baseline;                                         \
        statement;                                                                   \
        if (pseudo_reject_atomic(&mutated, (struct observation){                    \
                .kind = OBS_SYSCALL_EXIT, .generation = mutated.tasks[0].generation, \
                .result = -512L}, 0) != 0)                                           \
            return -1;                                                               \
    } while (0)
    REJECT_RESTART_MUTATION(mutated.case_name = "sim-restart");
    REJECT_RESTART_MUTATION(mutated.tasks[0].generation = 2);
    REJECT_RESTART_MUTATION(mutated.tasks[0].tid = 101);
    REJECT_RESTART_MUTATION(mutated.tasks[0].live = 0);
    REJECT_RESTART_MUTATION(mutated.tasks[0].exited = 1);
    REJECT_RESTART_MUTATION(mutated.tasks[0].wif = 1);
    REJECT_RESTART_MUTATION(mutated.tasks[0].superseded = 1);
    REJECT_RESTART_MUTATION(mutated.tasks[0].syscall_entry = 0);
    REJECT_RESTART_MUTATION(mutated.tasks[0].syscall_number = SYS_pause);
    REJECT_RESTART_MUTATION(mutated.tasks[0].fcntl = 0);
    REJECT_RESTART_MUTATION(mutated.tasks[0].fcntl = (int)mutated.next_invocation);
    REJECT_RESTART_MUTATION(mutated.next_invocation = 1);
    REJECT_RESTART_MUTATION(mutated.tasks[0].fcntl_command = F_GETFD);
    REJECT_RESTART_MUTATION(mutated.restart_state = 0);
    REJECT_RESTART_MUTATION(mutated.restart_observed = 1);
#undef REJECT_RESTART_MUTATION
    if (pseudo_reject_atomic(&baseline, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = -513L}, 0) != 0 ||
        pseudo_reject_atomic(&baseline, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = -514L}, 0) != 0 ||
        pseudo_reject_atomic(&baseline, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = -516L}, 0) != 0 ||
        pseudo_reject_atomic(&baseline, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = -512L}, 1) != 0)
        return -1;
    return 0;
}

static int restart_context_probe(const char *case_name, uint64_t generation,
                                 uint64_t command, int restart_state, long result,
                                 int expected_observed)
{
    unsigned char data[RECORD_SIZE * 32U];
    struct collector collector;
    negative_init(&collector, data, case_name);
    collector.restart_state = restart_state;
    if (negative_seed(&collector) != 0)
        return -1;
    if (generation != 1)
        collector.tasks[0].generation = generation;
    if (feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = generation, .parent = SYS_fcntl,
            .syscall_kind = 5,
            .invocation = 1, .arguments = {STDERR_FILENO, command, 0x1234}}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = generation, .result = result}, -2, 4) != 0 ||
        collector.tasks[0].fcntl != 1 || collector.tasks[0].syscall_entry != 1 ||
        collector.restart_observed != expected_observed)
        return -1;
    return 0;
}

static int restart_probe(long result)
{
    return restart_context_probe("sim-restart", 1, F_SETLKW, 0, result, 0);
}

static int cleanup_failure_ready_seed(struct collector *collector)
{
    return negative_seed(collector) == 0 &&
                   feed_observation(collector, (struct observation){
                       .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) == 0 &&
                   feed_observation(collector, (struct observation){
                       .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
                       .event_kind = 1, .tid = 20}) == 0 &&
                   feed_observation(collector, (struct observation){
                       .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}) == 0 &&
                   feed_observation(collector, (struct observation){
                       .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) == 0 &&
                   feed_observation(collector, (struct observation){
                       .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 5,
                       .invocation = 1, .parent = SYS_fcntl,
                       .arguments = {STDERR_FILENO, F_GETFD, 0}}) == 0;
}

static int cleanup_failure_mutation_checks(void)
{
    unsigned char data[RECORD_SIZE * 32U];
    struct collector baseline;
    negative_init(&baseline, data, "kernel-cleanup-failure");
    if (!cleanup_failure_ready_seed(&baseline) || !cleanup_failure_ready(&baseline))
        return -1;
#define REJECT_MUTATION(statement)                                                     \
    do {                                                                               \
        struct collector mutated = baseline;                                           \
        statement;                                                                     \
        if (cleanup_failure_ready(&mutated))                                           \
            return -1;                                                                 \
    } while (0)
    REJECT_MUTATION(mutated.case_name = "sim-negative");
    REJECT_MUTATION(mutated.task_count = 1);
    REJECT_MUTATION(mutated.creation_count = 0);
    REJECT_MUTATION(mutated.root_seen = 0);
    REJECT_MUTATION(mutated.saw_exec = 0);
    REJECT_MUTATION(mutated.tasks[0].generation = 3);
    REJECT_MUTATION(mutated.tasks[0].tid = 101);
    REJECT_MUTATION(mutated.tasks[0].live = 0);
    REJECT_MUTATION(mutated.tasks[0].exited = 1);
    REJECT_MUTATION(mutated.tasks[0].wif = 1);
    REJECT_MUTATION(mutated.tasks[0].superseded = 1);
    REJECT_MUTATION(mutated.tasks[0].terminal_wait_pending = 1);
    REJECT_MUTATION(mutated.tasks[0].cleanup_exit_seen = 1);
    REJECT_MUTATION(mutated.tasks[0].cleanup_parent_wif = 1);
    REJECT_MUTATION(mutated.tasks[0].syscall_entry = 0);
    REJECT_MUTATION(mutated.tasks[0].syscall_number = SYS_pause);
    REJECT_MUTATION(mutated.tasks[0].creation = 1);
    REJECT_MUTATION(mutated.tasks[0].fcntl = 0);
    REJECT_MUTATION(mutated.tasks[0].fcntl_fd = 1);
    REJECT_MUTATION(mutated.tasks[0].fcntl_command = F_GETFL);
    REJECT_MUTATION(mutated.tasks[0].fcntl_argument = 1);
    REJECT_MUTATION(mutated.cleanup_mode = 1);
    REJECT_MUTATION(mutated.cleanup_fault_observed = 1);
    REJECT_MUTATION(mutated.pending_stop_count = 1);
    REJECT_MUTATION(mutated.tasks[1].live = 0);
    REJECT_MUTATION(mutated.tasks[1].exited = 1);
    REJECT_MUTATION(mutated.tasks[1].wif = 1);
    REJECT_MUTATION(mutated.tasks[1].superseded = 1);
    REJECT_MUTATION(mutated.tasks[1].terminal_wait_pending = 1);
    REJECT_MUTATION(mutated.tasks[1].cleanup_exit_seen = 1);
    REJECT_MUTATION(mutated.tasks[1].cleanup_parent_wif = 1);
    REJECT_MUTATION(mutated.tasks[1].syscall_entry = 1);
    REJECT_MUTATION(mutated.tasks[1].syscall_number = SYS_pause);
    REJECT_MUTATION(mutated.tasks[1].creation = 1);
    REJECT_MUTATION(mutated.tasks[1].fcntl = 1);
    REJECT_MUTATION(mutated.creations[0].syscall_kind = 2);
    REJECT_MUTATION(mutated.creations[0].event_kind = 2);
    REJECT_MUTATION(mutated.creations[0].event = 0);
    REJECT_MUTATION(mutated.creations[0].joined = 0);
    REJECT_MUTATION(mutated.creations[0].result_seen = 0);
    REJECT_MUTATION(mutated.creations[0].done = 1);
    REJECT_MUTATION(mutated.creations[0].child_stop = 1);
    REJECT_MUTATION(mutated.creations[0].stop_tid = 21);
    REJECT_MUTATION(mutated.creations[0].child_tid = 21);
    REJECT_MUTATION(mutated.creations[0].child_generation = 3);
    REJECT_MUTATION(mutated.creations[0].parent = 2);
    REJECT_MUTATION(mutated.creations[0].cleanup_cancelled = 1);
    REJECT_MUTATION(mutated.creations[0].collector_kill = 1);
#undef REJECT_MUTATION
    return 0;
}

static int negative_transition_checks(void)
{
    unsigned char data[RECORD_SIZE * 32U];
    struct collector collector;
    const int seen_good[3] = {1, 1, 1};
    const int seen_bad[3] = {1, 0, 1};

    if (!bootstrap_fd_set_valid(seen_good) || bootstrap_fd_set_valid(seen_bad) ||
        probe_result_success(0) != 0 || probe_result_success(-1) == 0 ||
        probe_result_denied(-1, EPERM) != 0 || probe_result_denied(0, EPERM) == 0)
        return -1;
    if (ordinary_signal_checks(SIGUSR1) != 0 || ordinary_signal_checks(SIGUSR2) != 0 ||
        stopping_signal_checks() != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0)
        return -1;
    collector.cleanup_mode = 1;
    if (feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_WIF, .generation = 1, .status = 9}) != 0 ||
        collector.creations[0].result_seen != 0 || !collector.creations[0].cleanup_cancelled)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 20}) != 0)
        return -1;
    collector.cleanup_mode = 1;
    if (feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_UNKNOWN_WIF, .tid = 20, .status = 9}) != 0 ||
        collector.pending_stop_count != 0 || !collector.creations[0].cleanup_cancelled ||
        collector.creations[0].result_seen != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_CLEANUP_UNKNOWN_WIF, .tid = 20, .status = 9}, -1, 5) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_WIF, .generation = 1, .status = 9}) != 0)
        return -1;
    collector.wait_echild = 1;
    if (!containment_closed(&collector) ||
        lifecycle_complete(&collector))
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .tid = 20}) != 0)
        return -1;
    collector.cleanup_mode = 1;
    if (feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_UNKNOWN_WIF, .tid = 20, .status = 9}) != 0 ||
        collector.pending_stop_count != 0 || collector.creations[0].cleanup_cancelled ||
        collector.creations[0].result_seen != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_WIF, .generation = 1, .status = 9}) != 0)
        return -1;
    collector.wait_echild = 1;
    if (!containment_closed(&collector) || lifecycle_complete(&collector))
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 2,
            .event_kind = 1, .tid = 20}) != 0)
        return -1;
    collector.cleanup_mode = 1;
    if (negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_CLEANUP_UNKNOWN_WIF, .tid = 20, .status = 9}, -1, 8) != 0 ||
        collector.pending_stop_count != 0 || collector.creations[0].cleanup_cancelled ||
        collector.creations[1].cleanup_cancelled)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_reject(&collector, (struct observation){.kind = OBS_ROOT}, -1, 0) != 0 ||
        feed_observation(&collector, (struct observation){.kind = OBS_HEADER}) != 0 ||
        negative_reject(&collector, (struct observation){.kind = OBS_HEADER}, -1, 1) != 0 ||
        feed_observation(&collector, (struct observation){.kind = OBS_ROOT}) != 0 ||
        negative_reject(&collector, (struct observation){.kind = OBS_ROOT}, -1, 2) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_EXEC, .generation = 1, .exec_class = 1}) != 0 ||
        negative_reject(&collector, (struct observation){.kind = OBS_HEADER}, -1, 3) != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (feed_observation(&collector, (struct observation){.kind = OBS_HEADER}) != 0 ||
        feed_observation(&collector, (struct observation){.kind = OBS_ROOT}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .parent = SYS_execve}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_EXEC, .generation = 1, .exec_class = 1}, -1, 2) != 0 ||
        !collector.tasks[0].syscall_entry || collector.tasks[0].syscall_number != SYS_execve ||
        collector.journal.count != 2)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 99,
            .event_kind = 1, .tid = 20}, -1, 4) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 99, .creation = 1,
            .event_kind = 1, .tid = 20}, -1, 4) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 20}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 21}, -1, 5) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .creation = 1, .tid = 21}, -1, 5) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}, -1, 6) != 0 ||
        collector.creations[0].joined != 1 || collector.task_count != 2)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 3}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 2,
            .event_kind = 3, .tid = 20}, -1, 8) != 0 ||
        collector.creations[1].event != 0 || collector.task_count != 2)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 2, .status = 9}, -1, 7) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 0}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 9}, -1, 7) != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 9}, -1, 4) != 0 ||
        collector.tasks[0].creation != 1)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .parent = SYS_fcntl,
            .syscall_kind = 5, .invocation = 1,
            .arguments = {STDERR_FILENO, F_GETFD, 0}}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 9}, -1, 4) != 0 ||
        collector.tasks[0].fcntl != 1)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 4}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 3, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_COLLECTOR_KILL, .generation = 2}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 2, .status = 8}, -1, 7) != 0 ||
        collector.creations[0].collector_kill != 1 || collector.tasks[1].live != 1)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_EXIT_EVENT, .generation = 1, .status = 0}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 1}, -1, 4) != 0 ||
        collector.tasks[0].wif != 0 || collector.tasks[0].live != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_vfork_seed(&collector) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}, -1, 6) != 0 ||
        collector.tasks[0].syscall_entry != 1 || collector.tasks[0].creation != 1 ||
        collector.creations[0].result_seen != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_vfork_seed(&collector) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = -EAGAIN}, -1, 6) != 0 ||
        collector.tasks[0].creation != 1 || collector.tasks[0].syscall_entry != 1 ||
        collector.creations[0].joined != 1 || collector.creations[0].done != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_vfork_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){.kind = OBS_VFORK_DONE, .tid = 20}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_VFORK_DONE, .tid = 20}, -1, 8) != 0 ||
        collector.creations[0].done != 1 || collector.creations[0].result_seen != 1 ||
        collector.tasks[0].creation != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 2}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_EXIT_EVENT, .generation = 1, .status = 0}, -1, 4) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 9}, -1, 4) != 0 ||
        collector.tasks[0].syscall_entry != 1 || collector.journal.count != 4)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .parent = SYS_pause}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_EXIT_EVENT, .generation = 1, .status = 0}, -1, 3) != 0 ||
        collector.tasks[0].syscall_entry != 1 ||
        collector.tasks[0].syscall_number != SYS_pause || collector.journal.count != 3)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .parent = SYS_exit_group}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_EXIT_EVENT, .generation = 1, .status = 0}) != 0 ||
        collector.tasks[0].syscall_entry != 0 || collector.tasks[0].syscall_number != 0 ||
        !collector.tasks[0].exited || collector.journal.count != 4)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 0}) != 0 ||
        negative_reject(&collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = -512}, -2, 3) != 0 ||
        collector.tasks[0].syscall_entry != 1 || collector.tasks[0].creation != 0 ||
        collector.tasks[0].fcntl != 0)
        return -1;

    if (fcntl_binding_checks() != 0 || restart_context_matrix_checks() != 0 ||
        restart_probe(-512L) != 0 || restart_probe(-513L) != 0 ||
        restart_probe(-514L) != 0 || restart_probe(-516L) != 0)
        return -1;
    if (restart_context_probe("kernel-restart-reject", 1, F_SETLKW, 1, -512L, 1) != 0 ||
        restart_context_probe("kernel-restart-reject", 1, F_SETLKW, 1, -513L, 0) != 0 ||
        restart_context_probe("kernel-restart-reject", 1, F_SETLKW, 0, -512L, 0) != 0 ||
        restart_context_probe("kernel-restart-reject", 1, F_GETFD, 1, -512L, 0) != 0 ||
        restart_context_probe("kernel-restart-reject", 2, F_SETLKW, 1, -512L, 0) != 0)
        return -1;

    if (cleanup_failure_mutation_checks() != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_TERMINAL_PENDING, .generation = 1}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 2, .status = 0}, -1, 3) != 0 ||
        !collector.tasks[0].terminal_wait_pending || collector.journal.count != 3 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 0}) != 0 ||
        collector.tasks[0].terminal_wait_pending || collector.tasks[0].live ||
        !collector.tasks[0].wif || collector.journal.count != 4)
        return -1;
    collector.wait_echild = 1;
    if (!lifecycle_complete(&collector))
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 20}) != 0)
        return -1;
    {
        unsigned char before[RECORD_SIZE * 32U];
        memcpy(before, collector.journal.data, sizeof(before));
        if (feed_observation(&collector, (struct observation){
                .kind = OBS_CLEANUP_UNKNOWN_STOP, .tid = 20}) != 0 ||
            memcmp(before, collector.journal.data, sizeof(before)) != 0 ||
            collector.journal.count != 5 || collector.task_count != 1 ||
            collector.creations[0].joined || collector.pending_stop_count != 1)
            return -1;
        if (negative_reject_atomic(&collector, (struct observation){
                .kind = OBS_CLEANUP_UNKNOWN_STOP, .tid = 20}, -1, 5) != 0)
            return -1;
        collector.pending_stops[0].cleanup_resumed = 1;
        if (feed_observation(&collector, (struct observation){
                .kind = OBS_CLEANUP_UNKNOWN_STOP, .tid = 20}) != 0 ||
            collector.pending_stop_count != 1 || collector.pending_stops[0].cleanup_resumed ||
            collector.pending_stops[0].cleanup_exit_seen)
            return -1;
    }

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CHILD_STOP, .tid = 20}) != 0 ||
        collector.pending_stop_count != 1)
        return -1;
    {
        unsigned char before[RECORD_SIZE * 32U];
        memcpy(before, collector.journal.data, sizeof(before));
        if (feed_observation(&collector, (struct observation){
                .kind = OBS_CLEANUP_UNKNOWN_STOP, .tid = 20,
                .event_kind = PTRACE_EVENT_EXIT}) != 0 ||
            memcmp(before, collector.journal.data, sizeof(before)) != 0 ||
            collector.journal.count != 3 || collector.task_count != 1 ||
            collector.creation_count != 0 || collector.pending_stop_count != 1 ||
            !collector.pending_stops[0].cleanup_exit_seen ||
            collector.pending_stops[0].cleanup_resumed ||
            negative_reject_atomic(&collector, (struct observation){
                .kind = OBS_CLEANUP_UNKNOWN_STOP, .tid = 20,
                .event_kind = PTRACE_EVENT_EXIT}, -1, 3) != 0)
            return -1;
        collector.pending_stops[0].cleanup_resumed = 1;
        if (negative_reject_atomic(&collector, (struct observation){
                .kind = OBS_CLEANUP_UNKNOWN_STOP, .tid = 20}, -1, 3) != 0)
            return -1;
    }
    collector.cleanup_mode = 1;
    if (feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_UNKNOWN_WIF, .tid = 20, .status = 9}) != 0)
        return -1;
    if (collector.pending_stop_count != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_TERMINAL_PENDING, .generation = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 0}) != 0)
        return -1;
    collector.wait_echild = 1;
    if (!lifecycle_complete(&collector))
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_TERMINAL_PENDING, .generation = 1}) != 0)
        return -1;
    collector.wait_echild = 1;
    if (lifecycle_complete(&collector) || collector.pending_stop_count != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 0}) != 0 ||
        !lifecycle_complete(&collector))
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_EXIT_EVENT, .generation = 1, .status = 0}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_TERMINAL_PENDING, .generation = 1}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 1}, -1, 4) != 0 ||
        !collector.tasks[0].terminal_wait_pending || collector.journal.count != 4 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 0}) != 0)
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_TERMINAL_PENDING, .generation = 1}) != 0)
        return -1;
    collector.tasks[0].terminal_deadline = 0;
    if (!terminal_deadline_expired(&collector) || collector.journal.count != 3)
        return -1;

    negative_init(&collector, data, "sim-negative");
    collector.cleanup_mode = 1;
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_STOP, .generation = 1,
            .event_kind = PTRACE_EVENT_EXIT}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_CLEANUP_STOP, .generation = 1,
            .event_kind = PTRACE_EVENT_EXIT}, -1, 3) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_WIF, .generation = 1, .status = 9}) != 0 ||
        collector.journal.count != 3 || collector.tasks[0].live || !collector.tasks[0].wif)
        return -1;
    if (negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_CLEANUP_WIF, .generation = 1, .status = 0}, -1, 3) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_CLEANUP_WIF, .generation = 1, .status = 9}) != 0 ||
        negative_reject_atomic(&collector, (struct observation){
            .kind = OBS_CLEANUP_WIF, .generation = 1, .status = 9}, -1, 3) != 0)
        return -1;
    collector.wait_echild = 1;
    if (!lifecycle_complete(&collector))
        return -1;

    negative_init(&collector, data, "sim-negative");
    if (negative_seed(&collector) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_TERMINAL_PENDING, .generation = 1}) != 0 ||
        feed_observation(&collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 0}) != 0)
        return -1;
    collector.helper = 42;
    collector.helper_reaped = 1;
    collector.helper_status = 9;
    collector.wait_echild = 1;
    if (!lifecycle_complete(&collector))
        return -1;
    return 0;
}

static int kernel_collect(struct collector *collector)
{
    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    int helper_go[2] = {-1, -1};
    int helper_ack[2] = {-1, -1};
    int helper_signal = cleanup_signal_for_case(collector->case_name);
    int cleanup_signal = helper_signal != 0;
    int cleanup_failure = strcmp(collector->case_name, "kernel-cleanup-failure") == 0;
    pid_t *helper_pid_map = MAP_FAILED;
    pid_t collector_pid = getpid();
    pid_t expected_root_parent = collector_pid;
    pid_t root;
    int status;
    if ((cleanup_signal || cleanup_failure ||
         strcmp(collector->case_name, "kernel-restart-reject") == 0) &&
        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0)
        return -1;
    collector->helper_expected = cleanup_signal;
    if (pipe2(ready, O_CLOEXEC) != 0)
        return -1;
    if (pipe2(release, O_CLOEXEC) != 0) {
        close_if_open(&ready[0]);
        close_if_open(&ready[1]);
        return -1;
    }
    if (cleanup_signal &&
        (pipe2(helper_go, O_CLOEXEC) != 0 || pipe2(helper_ack, O_CLOEXEC) != 0)) {
        close(ready[0]);
        close(ready[1]);
        close(release[0]);
        close(release[1]);
        if (helper_go[0] >= 0)
            close(helper_go[0]);
        if (helper_go[1] >= 0)
            close(helper_go[1]);
        if (helper_ack[0] >= 0)
            close(helper_ack[0]);
        if (helper_ack[1] >= 0)
            close(helper_ack[1]);
        return -1;
    }
    if (cleanup_signal) {
        helper_pid_map = mmap(NULL, sizeof(*helper_pid_map), PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (helper_pid_map == MAP_FAILED) {
            close(ready[0]);
            close(ready[1]);
            close(release[0]);
            close(release[1]);
            close(helper_go[0]);
            close(helper_go[1]);
            close(helper_ack[0]);
            close(helper_ack[1]);
            return -1;
        }
        *helper_pid_map = 0;
    }
    collector->deadline = monotonic_ns() + 10000000000ULL;
    root = fork();
    if (root < 0) {
        close(ready[0]);
        close(ready[1]);
        close(release[0]);
        close(release[1]);
        if (cleanup_signal) {
            close(helper_go[0]);
            close(helper_go[1]);
            close(helper_ack[0]);
            close(helper_ack[1]);
            munmap(helper_pid_map, sizeof(*helper_pid_map));
        }
        return -1;
    }
    if (root == 0) {
        if (arm_pdeath(expected_root_parent) != 0)
            _exit(117);
        (void)child_ready(ready[0], ready[1], release[0], release[1], collector->output_fd,
                          collector->watchdog_fd, collector->case_name,
                          cleanup_signal ? helper_go[0] : -1,
                          cleanup_signal ? helper_go[1] : -1,
                          cleanup_signal ? helper_ack[0] : -1,
                          cleanup_signal ? helper_ack[1] : -1,
                          cleanup_signal ? helper_pid_map : NULL, collector_pid, helper_signal);
        _exit(117);
    }
    collector->root = root;
    {
        struct observation observation;
        struct transition_actions actions;
        memset(&observation, 0, sizeof(observation));
        observation.kind = OBS_HEADER;
        if (transition(collector, &observation, &actions) != 0)
            goto fail;
        observation.kind = OBS_ROOT;
        if (transition(collector, &observation, &actions) != 0)
            goto fail;
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        goto fail;
    close_if_open(&ready[1]);
    close_if_open(&release[0]);
    if (cleanup_signal) {
        close_if_open(&helper_go[0]);
        close_if_open(&helper_ack[1]);
        collector->helper_go_fd = helper_go[1];
        helper_go[1] = -1;
        collector->helper_ack_fd = helper_ack[0];
        helper_ack[0] = -1;
    }
    (void)setpgid(root, root);
    if (getpgid(root) != root || write_watchdog(collector->watchdog_fd, 1, root) != 0) {
        goto fail;
    }
    collector->watchdog_fd = -1;
    if (wait_ready(ready[0], collector->deadline) != 0) {
        goto fail;
    }
    if (cleanup_signal) {
        __sync_synchronize();
        if (helper_pid_map == MAP_FAILED || *helper_pid_map <= 0 || *helper_pid_map == root)
            goto fail;
        collector->helper = *helper_pid_map;
        collector->helper_candidate = collector->helper;
        munmap(helper_pid_map, sizeof(*helper_pid_map));
        helper_pid_map = MAP_FAILED;
    }
    close_if_open(&ready[0]);
    if (ptrace(PTRACE_SEIZE, root, 0, (void *)(uintptr_t)OPTS) != 0) {
        int saved = errno;
        if (collector->helper_go_fd >= 0) {
            close(collector->helper_go_fd);
            collector->helper_go_fd = -1;
        }
        if (saved == ESRCH)
            (void)mark_terminal_pending(collector, 1);
        if (drain_wait(collector, DRAIN_CLEANUP, root, NULL) != 0)
            goto fail;
        close_if_open(&release[1]);
        close_if_open(&collector->helper_ack_fd);
        if (saved == EPERM || saved == EACCES) {
            fprintf(stderr, "bs2b-s9-native-unrun:ptrace-seize-denied\n");
            return 77;
        }
        if (saved == ENOSYS || saved == EINVAL) {
            fprintf(stderr, "bs2b-s9-native-unrun:ptrace-seize-unsupported\n");
            return 77;
        }
        return -1;
    }
    if (ptrace(PTRACE_INTERRUPT, root, 0, 0) != 0) {
        if (errno != ESRCH || mark_terminal_pending(collector, 1) != 0)
            goto fail;
        goto fail;
    }
    if (drain_wait(collector, DRAIN_INITIAL_STOP, root, &status) != 0)
        goto fail;
    if (!WIFSTOPPED(status) || (status >> 16) != PTRACE_EVENT_STOP ||
        WSTOPSIG(status) != SIGTRAP) {
        goto fail;
    }
    if (write(release[1], "R", 1) != 1) {
        goto fail;
    }
    close_if_open(&release[1]);
    {
        struct transition_actions actions;
        memset(&actions, 0, sizeof(actions));
        actions.resume = 1;
        actions.resume_cont = 1;
        if (execute_actions(collector, root, 1, &actions) != 0)
            goto fail;
    }
    {
        int drain_result = drain_wait(collector, DRAIN_NORMAL, root, NULL);
        if (drain_result == -2)
            goto expected_fail;
        if (drain_result == 1)
            goto cleanup_signal_path;
        if (drain_result != 0)
            goto fail;
    }
cleanup_signal_path:
    if (cleanup_signal && stop_requested) {
        if (finish_cleanup_signal(collector) != 0 ||
            drain_wait(collector, DRAIN_CLEANUP, root, NULL) != 0)
            goto fail;
        collector->expected_rejection = 1;
        return 0;
    }
    if (stop_requested || monotonic_ns() >= collector->deadline) {
        goto fail;
    }
    if (cleanup_signal || strcmp(collector->case_name, "kernel-restart-reject") == 0 ||
        strcmp(collector->case_name, "kernel-group-stop-reject") == 0 ||
        strcmp(collector->case_name, "kernel-cleanup-failure") == 0)
        goto fail;
    if (finish_tasks(collector) != 0 || !lifecycle_complete(collector)) {
        goto fail;
    }
    close_if_open(&release[1]);
    return 0;
expected_fail:
    {
        int cleanup_result = drain_wait(collector, DRAIN_CLEANUP, root, NULL);
        int expected_observed =
            (strcmp(collector->case_name, "kernel-restart-reject") == 0 &&
             collector->restart_observed) ||
            (strcmp(collector->case_name, "kernel-group-stop-reject") == 0 &&
             collector->group_stop_observed) ||
            (strcmp(collector->case_name, "kernel-cleanup-failure") == 0 &&
             collector->cleanup_fault_observed);
        if (!expected_observed || cleanup_result != 0) {
            close_if_open(&ready[0]);
            close_if_open(&ready[1]);
            close_if_open(&release[0]);
            close_if_open(&release[1]);
            close_if_open(&helper_go[0]);
            close_if_open(&helper_go[1]);
            close_if_open(&helper_ack[0]);
            close_if_open(&helper_ack[1]);
            close_if_open(&collector->helper_go_fd);
            close_if_open(&collector->helper_ack_fd);
            return -1;
        }
    }
    collector->expected_rejection = 1;
    close_if_open(&ready[0]);
    close_if_open(&ready[1]);
    close_if_open(&release[0]);
    close_if_open(&release[1]);
    close_if_open(&helper_go[0]);
    close_if_open(&helper_go[1]);
    close_if_open(&helper_ack[0]);
    close_if_open(&helper_ack[1]);
    close_if_open(&collector->helper_go_fd);
    close_if_open(&collector->helper_ack_fd);
    return 0;
fail:
    if (cleanup_signal && helper_pid_map != MAP_FAILED) {
        __sync_synchronize();
        if (*helper_pid_map > 0 && *helper_pid_map != root)
            collector->helper = *helper_pid_map;
        if (*helper_pid_map > 0 && *helper_pid_map != root)
            collector->helper_candidate = *helper_pid_map;
        munmap(helper_pid_map, sizeof(*helper_pid_map));
        helper_pid_map = MAP_FAILED;
    }
    if (collector->helper < 0 && collector->helper_candidate > 0)
        collector->helper = collector->helper_candidate;
    close_if_open(&ready[0]);
    close_if_open(&ready[1]);
    close_if_open(&release[0]);
    close_if_open(&release[1]);
    close_if_open(&helper_go[0]);
    close_if_open(&helper_go[1]);
    close_if_open(&helper_ack[0]);
    close_if_open(&helper_ack[1]);
    if (collector->helper_go_fd >= 0) {
        close(collector->helper_go_fd);
        collector->helper_go_fd = -1;
    }
    if (collector->helper_ack_fd >= 0) {
        close(collector->helper_ack_fd);
        collector->helper_ack_fd = -1;
    }
    (void)drain_wait(collector, DRAIN_CLEANUP, root, NULL);
    return -1;
}

static int simulation(struct collector *collector)
{
    struct observation observation = {0};
    if (negative_transition_checks() != 0)
        return -1;
    if (feed_observation(collector, (struct observation){.kind = OBS_HEADER}) != 0 ||
        feed_observation(collector, (struct observation){.kind = OBS_ROOT}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_EXEC, .generation = 1, .exec_class = 1}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 0}) != 0)
        return -1;
    if (strcmp(collector->case_name, "sim-restart") == 0) {
        static const long restart_results[] = {-512L, -513L, -514L, -516L};
        for (size_t i = 0; i != sizeof(restart_results) / sizeof(restart_results[0]); ++i)
            if (restart_probe(restart_results[i]) != 0)
                return -1;
        return 0;
    }
    if (strcmp(collector->case_name, "sim-tid-reuse") == 0) {
        observation = (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1};
        if (feed_observation(collector, observation) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
                .event_kind = 1, .tid = 20}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_CHILD_STOP, .creation = 1, .tid = 20}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_EXIT_EVENT, .generation = 2, .status = 0}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_FINAL_WIF, .generation = 2, .status = 0}) != 0)
            return -1;
        if (feed_observation(collector, (struct observation){
                .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 3}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 2,
                .event_kind = 3, .tid = 20}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_CHILD_STOP, .creation = 2, .tid = 20}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_EXIT_EVENT, .generation = 3, .status = 0}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_FINAL_WIF, .generation = 3, .status = 0}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_EXIT_EVENT, .generation = 1, .status = 0}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_FINAL_WIF, .generation = 1, .status = 0}) != 0)
            return -1;
        return 0;
    }
    observation = (struct observation){
        .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 1};
    if (feed_observation(collector, observation) != 0)
        return -1;
    if (strcmp(collector->case_name, "sim-stop-first") == 0) {
        if (feed_observation(collector, (struct observation){
                .kind = OBS_CHILD_STOP, .tid = 20}) != 0)
            return -1;
    }
    if (feed_observation(collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 1,
            .event_kind = 1, .tid = 20}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 20}) != 0 ||
        (strcmp(collector->case_name, "sim-stop-first") != 0 &&
         feed_observation(collector, (struct observation){
             .kind = OBS_CHILD_STOP, .tid = 20}) != 0) ||
        feed_observation(collector, (struct observation){
            .kind = OBS_EXIT_EVENT, .generation = 2, .status = 0}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 2, .status = 0}) != 0)
        return -1;

    if (feed_observation(collector, (struct observation){
            .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 4}) != 0)
        return -1;
    if (strcmp(collector->case_name, "sim-stop-first") == 0) {
        if (feed_observation(collector, (struct observation){
                .kind = OBS_CHILD_STOP, .tid = 30}) != 0)
            return -1;
    }
    if (feed_observation(collector, (struct observation){
            .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 2,
            .event_kind = 3, .tid = 30}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 30}) != 0 ||
        (strcmp(collector->case_name, "sim-stop-first") != 0 &&
         feed_observation(collector, (struct observation){
             .kind = OBS_CHILD_STOP, .tid = 30}) != 0) ||
        feed_observation(collector, (struct observation){
            .kind = OBS_EXIT_EVENT, .generation = 3, .status = 0}) != 0 ||
        feed_observation(collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 3, .status = 0}) != 0)
        return -1;

    if (strcmp(collector->case_name, "sim-event-first") == 0) {
        if (feed_observation(collector, (struct observation){
                .kind = OBS_SYSCALL_ENTRY, .generation = 1, .syscall_kind = 4}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_CREATE_EVENT, .generation = 1, .creation = 3,
                .event_kind = 3, .tid = 40}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_SYSCALL_EXIT, .generation = 1, .result = 40}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_CHILD_STOP, .tid = 40}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_COLLECTOR_KILL, .generation = 4}) != 0 ||
            feed_observation(collector, (struct observation){
                .kind = OBS_FINAL_WIF, .generation = 4, .status = 9}) != 0)
            return -1;
    }
    return feed_observation(collector, (struct observation){
        .kind = OBS_EXIT_EVENT, .generation = 1, .status = 0}) == 0 &&
        feed_observation(collector, (struct observation){
            .kind = OBS_FINAL_WIF, .generation = 1, .status = 0}) == 0 ? 0 : -1;
}

static int run_self_test(const char *case_name, int output_fd, int watchdog_fd)
{
    struct collector collector;
    off_t original_offset;
    struct stat identity;
    struct sigaction action;
    int result;
    memset(&collector, 0, sizeof(collector));
    collector.case_name = case_name;
    collector.output_fd = output_fd;
    collector.watchdog_fd = watchdog_fd;
    collector.helper = -1;
    collector.helper_go_fd = -1;
    collector.helper_ack_fd = -1;
    collector.next_generation = 1;
    collector.next_creation = 1;
    collector.next_invocation = 1;
    collector.next_group = 1;
    collector.journal.data = calloc(MAX_RECORDS, RECORD_SIZE);
    if (collector.journal.data == NULL)
        return 1;
    stop_requested = 0;
    received_signal = 0;
    if (validate_output(output_fd, &original_offset, &identity, &collector.output_flags) != 0 ||
        validate_watchdog(watchdog_fd, output_fd) != 0 ||
        snapshot_bootstrap_identity(&collector) != 0)
        goto refused;
    collector.output_offset = original_offset;
    collector.output_identity = identity;
    if (fcntl(output_fd, F_SETFD, fcntl(output_fd, F_GETFD) | FD_CLOEXEC) != 0 ||
        fcntl(watchdog_fd, F_SETFD, fcntl(watchdog_fd, F_GETFD) | FD_CLOEXEC) != 0)
        goto refused;
    memset(&action, 0, sizeof(action));
    action.sa_handler = latch_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGHUP, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0)
        goto failed;
    if (valid_kernel_case(case_name)) {
        result = kernel_collect(&collector);
    } else if (strcmp(case_name, "review-policy-bpf") == 0) {
        if (write_watchdog(watchdog_fd, 0, 0) != 0)
            goto failed;
        collector.watchdog_fd = -1;
        result = export_policy(&collector);
    } else {
        if (write_watchdog(watchdog_fd, 0, 0) != 0)
            goto failed;
        collector.watchdog_fd = -1;
        result = simulation(&collector);
        if (strcmp(case_name, "sim-restart") != 0 && result == 0)
            result = flush_journal(&collector);
    }
    if (collector.watchdog_fd >= 0)
        close(collector.watchdog_fd);
    if (result == 77) {
        free(collector.journal.data);
        return 77;
    }
    if (result != 0)
        goto failed;
    if (strcmp(case_name, "review-policy-bpf") != 0 && valid_kernel_case(case_name) &&
        !collector.expected_rejection && flush_journal(&collector) != 0)
        goto failed;
    if (lseek(output_fd, original_offset, SEEK_SET) < 0)
        goto failed;
    free(collector.journal.data);
    printf("bs2b-s9-native-self-test-ok:%s\n", case_name);
    return 0;
refused:
    if (collector.watchdog_fd >= 0)
        close(collector.watchdog_fd);
    free(collector.journal.data);
    return 77;
failed:
    if (collector.watchdog_fd >= 0)
        close(collector.watchdog_fd);
    free(collector.journal.data);
    fputs("bs2b-s9-native-self-test-failed\n", stderr);
    return 1;
}

int main(int argc, char **argv)
{
    int output_fd;
    int watchdog_fd;
    if (argc == 3 && strcmp(argv[1], "internal-workload") == 0 &&
        valid_internal_workload_case(argv[2]))
        return internal_workload(argv[2]);
    if (argc != 5 || strcmp(argv[1], "self-test") != 0 || !valid_case(argv[2]) ||
        parse_fd(argv[3], &output_fd) != 0 || parse_fd(argv[4], &watchdog_fd) != 0)
        return 77;
    return run_self_test(argv[2], output_fd, watchdog_fd);
}
