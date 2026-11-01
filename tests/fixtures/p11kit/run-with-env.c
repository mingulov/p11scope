/* SPDX-License-Identifier: GPL-3.0-or-later */
/* run-with-env: minimal exec wrapper for the p11-kit `run` cell.
 * usage: run-with-env NAME=VALUE... -- prog args...
 * A root observer starts `run` children with an allowlisted environment
 * (PATH, LANG, LC_ALL, TERM, TZ, SOFTHSM2_CONF), which strips the p11-kit
 * user-config and spy variables the transparency cells need. This wrapper
 * is the observed CMD: it sets the given variables and execs the workload
 * in place (same pid), so READY/LEDGER custody is unaffected. It maps no
 * providers and makes no PKCS#11 calls itself. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int sep = -1;
  for (int i = 1; i < argc; i++)
    if (strcmp(argv[i], "--") == 0) { sep = i; break; }
  if (sep < 0 || sep + 1 >= argc) {
    fprintf(stderr, "usage: run-with-env NAME=VALUE... -- prog args...\n");
    return 2;
  }
  for (int i = 1; i < sep; i++) {
    char *eq = strchr(argv[i], '=');
    if (!eq || eq == argv[i]) { fprintf(stderr, "bad env: %s\n", argv[i]); return 2; }
    *eq = '\0';
    if (setenv(argv[i], eq + 1, 1)) { perror("setenv"); return 1; }
  }
  execvp(argv[sep + 1], &argv[sep + 1]);
  perror("execvp");
  return 127;
}
