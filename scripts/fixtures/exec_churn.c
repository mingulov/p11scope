/* SPDX-License-Identifier: GPL-3.0-or-later */
/* exec_churn: fork and exec at a fixed rate (Task 6 C5.5, measurements M3/M4).
 *
 * usage: exec_churn RATE SECONDS SHARE_PCT LEDGER [-- CALLER ARGV...]
 *
 * Every tick of an absolute CLOCK_MONOTONIC schedule (1/RATE s apart) forks
 * one child. SHARE_PCT percent of the children, spread evenly over the ticks,
 * exec CALLER ARGV (a provider caller, e.g. `gated MODULE 1 0 -`); the rest
 * exec /bin/true, unrelated to any provider. SHARE_PCT 0 needs no CALLER.
 * SECONDS 0 runs until SIGTERM or SIGINT; either signal also ends a timed run
 * early. Children are reaped as they exit and once more, bounded, at the end.
 *
 * LEDGER (the independent per-pid record an oracle checks false joins against):
 *   EXEC pid=P kind=provider|unrelated fork_ns=T   (CLOCK_MONOTONIC, before fork)
 *   EXIT pid=P status=S reap_ns=T                  (raw wait status, when reaped)
 *   SUMMARY target_rate=R seconds=S share_pct=P execs=N provider=N unrelated=N
 *           exec_fail=N nonzero=N signaled=N unreaped=N late_ticks=N late_max_us=N
 *           dropped_ticks=N achieved_rate=R
 * A tick more than 1 ms behind its schedule is late; a schedule more than 100
 * ticks behind is resynchronised and the skipped ticks are counted as dropped,
 * so a stalled host never bursts. exec_fail counts children that exited 127
 * (a failed execv); the analysis refuses a run with any, or below 90% of RATE.
 *
 * Exit: 0 after writing SUMMARY, 2 usage, 1 ledger or fork failure. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void on_stop(int signal_number) { (void)signal_number; stop = 1; }

static unsigned long long mono_ns(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (unsigned long long)now.tv_sec * 1000000000ull + (unsigned long long)now.tv_nsec;
}

static unsigned long exec_fail, nonzero, signaled, reaped;

static void reap(FILE *ledger, int options) {
  int status;
  pid_t pid;
  while ((pid = waitpid(-1, &status, options)) > 0) {
    reaped++;
    fprintf(ledger, "EXIT pid=%d status=%d reap_ns=%llu\n", (int)pid, status, mono_ns());
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
      exec_fail++;
    else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
      nonzero++;
    else if (WIFSIGNALED(status))
      signaled++;
  }
}

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: exec_churn RATE SECONDS SHARE_PCT LEDGER [-- CALLER ARGV...]\n");
    return 2;
  }
  long rate = atol(argv[1]), seconds = atol(argv[2]), share = atol(argv[3]);
  char **caller = NULL;
  if (argc > 5) {
    if (strcmp(argv[5], "--") != 0 || argc < 7) {
      fprintf(stderr, "exec_churn: CALLER ARGV must follow --\n");
      return 2;
    }
    caller = argv + 6;
  }
  if (rate <= 0 || rate > 100000 || seconds < 0 || share < 0 || share > 100 || (share > 0 && !caller)) {
    fprintf(stderr, "exec_churn: need 0 < RATE <= 100000, SECONDS >= 0, 0 <= SHARE_PCT <= 100, and a CALLER when SHARE_PCT > 0\n");
    return 2;
  }
  FILE *ledger = fopen(argv[4], "w");
  if (!ledger) {
    perror("exec_churn: ledger");
    return 1;
  }
  setvbuf(ledger, NULL, _IOFBF, 1 << 20);
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = on_stop;
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);

  static char *const unrelated[] = {"true", NULL};
  const unsigned long long period = 1000000000ull / (unsigned long long)rate;
  const unsigned long long start = mono_ns();
  const unsigned long long end = seconds ? start + (unsigned long long)seconds * 1000000000ull : 0;
  unsigned long long next = start, late_max = 0;
  unsigned long ticks = 0, provider = 0, late = 0, dropped = 0;
  while (!stop) {
    unsigned long long now = mono_ns();
    if (end && now >= end)
      break;
    if (now < next) {
      struct timespec at = {(time_t)(next / 1000000000ull), (long)(next % 1000000000ull)};
      if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &at, NULL) != 0)
        continue; /* EINTR: re-check stop */
      now = mono_ns();
      if (end && now >= end)
        break;
    }
    if (now > next + 1000000ull) {
      late++;
      if (now - next > late_max)
        late_max = now - next;
    }
    if (now > next + 100 * period) {
      unsigned long long skipped = (now - next) / period;
      dropped += skipped;
      next += skipped * period;
    }
    /* Even spread: tick i calls the provider when floor(i*P/100) advances. */
    int is_provider = share > 0 && (ticks + 1) * share / 100 != ticks * share / 100;
    unsigned long long fork_ns = mono_ns();
    pid_t pid = fork();
    if (pid < 0) {
      perror("exec_churn: fork");
      break;
    }
    if (pid == 0) { /* execv or _exit: neither flushes the inherited ledger buffer */
      if (is_provider)
        execv(caller[0], caller);
      else
        execv("/bin/true", unrelated);
      _exit(127);
    }
    fprintf(ledger, "EXEC pid=%d kind=%s fork_ns=%llu\n", (int)pid,
            is_provider ? "provider" : "unrelated", fork_ns);
    ticks++;
    provider += (unsigned long)is_provider;
    next += period;
    reap(ledger, WNOHANG);
  }
  const unsigned long long stopped = mono_ns();
  /* Bounded final reap: a provider caller gets 30 s to finish. */
  while (reaped < ticks && mono_ns() < stopped + 30000000000ull) {
    reap(ledger, WNOHANG);
    if (reaped < ticks)
      usleep(10000);
  }
  double elapsed = (double)(stopped - start) / 1e9;
  fprintf(ledger,
          "SUMMARY target_rate=%ld seconds=%.3f share_pct=%ld execs=%lu provider=%lu unrelated=%lu "
          "exec_fail=%lu nonzero=%lu signaled=%lu unreaped=%lu late_ticks=%lu late_max_us=%llu "
          "dropped_ticks=%lu achieved_rate=%.1f\n",
          rate, elapsed, share, ticks, provider, ticks - provider, exec_fail, nonzero, signaled,
          ticks - reaped, late, late_max / 1000ull, dropped, elapsed > 0 ? (double)ticks / elapsed : 0.0);
  if (fclose(ledger) != 0) {
    perror("exec_churn: ledger close");
    return 1;
  }
  return 0;
}
