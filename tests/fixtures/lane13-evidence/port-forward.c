#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
extern char **environ;
static void on_signal(int signal_number) {
    (void)signal_number;
    _exit(0);
}
static int publish_identity(int argc, char **argv) {
    const char *state = getenv("D2_STATE");
    const char *owner = getenv("D2_OWNER_ID");
    const char *evidence = getenv("P11SCOPE_LANE_EVIDENCE_DIR");
    if (state == NULL || owner == NULL || evidence == NULL || argc < 2) return -1;
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", (long)getpid());
    FILE *stream = fopen(stat_path, "r");
    if (stream == NULL) return -1;
    char raw[8192];
    if (fgets(raw, sizeof(raw), stream) == NULL || fclose(stream) != 0) return -1;
    char *tail = strrchr(raw, ')');
    if (tail == NULL || tail[1] != ' ') return -1;
    long ppid = 0, pgid = 0, sid = 0;
    unsigned long long starttime = 0;
    char *save = NULL;
    char *token = strtok_r(tail + 2, " ", &save);
    for (int field = 0; token != NULL && field <= 19; ++field) {
        if (field == 1) ppid = strtol(token, NULL, 10);
        if (field == 2) pgid = strtol(token, NULL, 10);
        if (field == 3) sid = strtol(token, NULL, 10);
        if (field == 19) starttime = strtoull(token, NULL, 10);
        token = strtok_r(NULL, " ", &save);
    }
    if (ppid <= 0 || pgid <= 0 || sid <= 0 || starttime == 0) return -1;
    char exe[4096];
    ssize_t exe_length = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (exe_length <= 0 || (size_t)exe_length >= sizeof(exe)) return -1;
    exe[exe_length] = '\0';
    char record[16384];
    int length = snprintf(
        record, sizeof(record),
        "{\"version\":1,\"record_id\":\"%s:native-port-forward:%ld:%llu\","
        "\"owner\":\"%s\",\"evidence\":\"%s\",\"kind\":\"native-port-forward\","
        "\"pid\":%ld,\"starttime\":%llu,\"ppid\":%ld,\"pgid\":%ld,\"sid\":%ld,"
        "\"exe\":\"%s\","
        "\"argv\":[",
        owner, (long)getpid(), starttime, owner, evidence, (long)getpid(), starttime,
        ppid, pgid, sid, exe);
    if (length <= 0 || (size_t)length >= sizeof(record)) return -1;
    size_t used = (size_t)length;
    for (int index = 0; index < argc; ++index) {
        length = snprintf(record + used, sizeof(record) - used, "%s\"%s\"",
                          index == 0 ? "" : ",", argv[index]);
        if (length <= 0 || (size_t)length >= sizeof(record) - used) return -1;
        used += (size_t)length;
    }
    length = snprintf(record + used, sizeof(record) - used, "]}\n");
    if (length <= 0 || (size_t)length >= sizeof(record) - used) return -1;
    used += (size_t)length;
    char ledger[4096];
    char ready[4096];
    if (snprintf(ledger, sizeof(ledger), "%s/fixture-pids", state) >= (int)sizeof(ledger)
        || snprintf(ready, sizeof(ready), "%s/portforward-ready", state) >= (int)sizeof(ready)) return -1;
    int fd = open(ledger, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || write(fd, record, used) != (ssize_t)used || fsync(fd) != 0 || close(fd) != 0) return -1;
    fd = open(ready, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, record, used) != (ssize_t)used || fsync(fd) != 0 || close(fd) != 0) return -1;
    return 0;
}
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "port-forward") == 0) {
        if (getenv("D2_PORT_FORWARD_HOLD") != 0) {
            signal(SIGINT, SIG_IGN);
            signal(SIGTERM, SIG_IGN);
        } else {
            signal(SIGINT, on_signal);
            signal(SIGTERM, on_signal);
        }
        /* A safety lifetime only: the gate's TERM (or the harness's KILL for
         * a TERM-ignoring hold) ends every passing run first, and an alarm
         * exit is always nonpass. The harness scales it apart from the
         * dispatch holds, which share D2_HOLD_SECONDS as the fallback. */
        const char *hold = getenv("D2_PORT_FORWARD_SECONDS");
        if (hold == 0) hold = getenv("D2_HOLD_SECONDS");
        alarm(hold == 0 ? 5U : (unsigned int)strtoul(hold, 0, 10));
        if (publish_identity(argc, argv) != 0) return 125;
        for (;;) pause();
    }
    char *dispatch = getenv("D2_DISPATCH_PATH");
    if (dispatch == 0) return 127;
    setenv("D2_COMMAND_NAME", "kubectl", 1);
    execve(dispatch, argv, environ);
    return 127;
}
