/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_EXEC_TASK_H
#define P11SCOPE_EXEC_TASK_H

/* A finite kernel-only predicate, never a task/mm identity receipt. */
unsigned int p11_exec_dumpability(void);

/* 6.14 Option B: exec-time executable file identity. Reads
 * current->mm->exe_file's raw s_dev and i_ino into the out-words.
 * Returns nonzero only when every read succeeds; any missing field,
 * wrong size, failed read, or null pointer yields 0 with the
 * out-words untouched. Kernel file metadata only: no path, argv,
 * environment, or user-memory read. The name avoids the p11_exec_
 * prefix on purpose: that global namespace requires no-argument
 * helpers, and this one needs two out-words. */
unsigned int p11_exe_identity(unsigned long *dev, unsigned long *ino);

#endif
