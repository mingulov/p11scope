/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* patch-unmapped: flip one byte in an unmapped ELF section, in place.
 * usage: patch-unmapped FILE
 * Test-only fixture for the kind copy-up negative cell: the workload stages
 * the provider into its own writable layer, maps it (stale side), then
 * rewrites one byte in place (same inode, same size) so the file's identity
 * genuinely changes under the observer's pin. The target is the first
 * unmapped (non-SHF_ALLOC) PROGBITS/NOTE section that is not the section-name
 * table itself — .gnu_debuglink on a stripped Ubuntu SoftHSM — so no mapped
 * page changes and both ledger sides run identical code; only the file
 * digest changes. Prints the patched section and file offset. Exit 2 on
 * usage errors, 1 when the file has no usable unmapped section. */
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *msg) { fprintf(stderr, "patch-unmapped: %s\n", msg); return 1; }

int main(int argc, char **argv) {
  if (argc != 2) { fprintf(stderr, "usage: patch-unmapped FILE\n"); return 2; }
  int fd = open(argv[1], O_RDWR);
  if (fd < 0) { perror("patch-unmapped: open"); return 1; }
  Elf64_Ehdr ehdr;
  if (read(fd, &ehdr, sizeof(ehdr)) != (ssize_t)sizeof(ehdr)) return fail("short ELF header");
  if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return fail("not an ELF file");
  if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 || ehdr.e_shentsize != sizeof(Elf64_Shdr) ||
      ehdr.e_shnum == 0 || ehdr.e_shstrndx >= ehdr.e_shnum)
    return fail("unsupported ELF layout");
  Elf64_Shdr *shdrs = malloc(ehdr.e_shentsize * ehdr.e_shnum);
  if (!shdrs) return fail("out of memory");
  if (pread(fd, shdrs, ehdr.e_shentsize * ehdr.e_shnum, ehdr.e_shoff) !=
      (ssize_t)(ehdr.e_shentsize * ehdr.e_shnum))
    return fail("short section table");
  Elf64_Shdr str = shdrs[ehdr.e_shstrndx];
  char *names = malloc(str.sh_size ? str.sh_size : 1);
  if (!names) return fail("out of memory");
  if (str.sh_size && pread(fd, names, str.sh_size, str.sh_offset) != (ssize_t)str.sh_size)
    return fail("short section names");
  int target = -1;
  for (int i = 0; i < (int)ehdr.e_shnum; i++) {
    if (i == (int)ehdr.e_shstrndx || (shdrs[i].sh_flags & SHF_ALLOC) != 0 ||
        shdrs[i].sh_type == SHT_NOBITS || shdrs[i].sh_size < 2)
      continue;
    if (shdrs[i].sh_type != SHT_PROGBITS && shdrs[i].sh_type != SHT_NOTE)
      continue;
    if (target < 0 || (shdrs[i].sh_name < str.sh_size &&
                       !strcmp(names + shdrs[i].sh_name, ".gnu_debuglink"))) {
      target = i;
      if (shdrs[i].sh_name < str.sh_size && !strcmp(names + shdrs[i].sh_name, ".gnu_debuglink"))
        break;
    }
  }
  const char *name = (target >= 0 && shdrs[target].sh_name < str.sh_size)
      ? names + shdrs[target].sh_name : "?";
  /* Flip the first byte that is neither NUL nor 0xff, so the change is a
   * real content delta in both directions and never a truncation. */
  int flipped = 0;
  if (target >= 0) {
    for (Elf64_Xword i = 0; i < shdrs[target].sh_size; i++) {
      unsigned char byte;
      if (pread(fd, &byte, 1, shdrs[target].sh_offset + i) != 1) break;
      if (byte != 0 && byte != 0xff) {
        unsigned char out = (unsigned char)(byte ^ 0x01);
        if (pwrite(fd, &out, 1, shdrs[target].sh_offset + i) != 1) {
          perror("patch-unmapped: pwrite");
          free(shdrs);
          free(names);
          close(fd);
          return 1;
        }
        printf("patched %s file offset %llu: 0x%02x -> 0x%02x\n", name,
               (unsigned long long)(shdrs[target].sh_offset + i), byte, out);
        flipped = 1;
        break;
      }
    }
  }
  free(shdrs);
  free(names);
  close(fd);
  if (!flipped) return fail("no usable unmapped section");
  return 0;
}
