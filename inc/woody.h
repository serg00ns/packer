#pragma once
#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#define OUT_FILE "woody"
#define KEY_LEN  9

void *x_mmap_ro(int fd, size_t size);
int   x_get_file_size(int fd, size_t *out);

int   elf_basic_checks(const unsigned char *p, size_t size);
int   elf_find_exec_segment(const unsigned char *p, Elf64_Phdr *out_ph, int *out_idx);
int   elf_find_last_load_segment(const unsigned char *p, Elf64_Phdr *out_ph, int *out_idx);

int   pack_buffer(const unsigned char *in, size_t in_size, const char *out_path);
