#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "woody.h"

void *x_mmap_ro(int fd, size_t size) {
    return mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
}

int x_get_file_size(int fd, size_t *out) {
    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) return -1;
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    *out = (size_t)end;
    return 0;
}

static const Elf64_Phdr* phdr_at(const unsigned char *p, const Elf64_Ehdr *eh, int idx) {
    return (const Elf64_Phdr*)(p + eh->e_phoff) + idx;
}

int elf_basic_checks(const unsigned char *p, size_t size) {
    if (size < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)p;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (eh->e_ident[EI_DATA]  != ELFDATA2LSB) return -1;
    if (eh->e_machine != EM_X86_64) return -1;
    if (!(eh->e_type == ET_EXEC || eh->e_type == ET_DYN)) return -1;
    if (eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf64_Phdr) > size) return -1;
    return 0;
}

int elf_find_exec_segment(const unsigned char *p, Elf64_Phdr *out_ph, int *out_idx) {
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)p;
    for (int i = 0; i < eh->e_phnum; ++i) {
        const Elf64_Phdr *ph = phdr_at(p, eh, i);
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) {
            if (out_ph)  *out_ph  = *ph;
            if (out_idx) *out_idx = i;
            return 0;
        }
    }
    return -1;
}

int elf_find_last_load_segment(const unsigned char *p, Elf64_Phdr *out_ph, int *out_idx) {
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)p;
    int last = -1;
    Elf64_Phdr tmp = (Elf64_Phdr){0};
    for (int i = 0; i < eh->e_phnum; ++i) {
        const Elf64_Phdr *ph = phdr_at(p, eh, i);
        if (ph->p_type == PT_LOAD) {
            last = i;
            tmp = *ph;
        }
    }
    if (last < 0) return -1;
    if (out_ph)  *out_ph  = tmp;
    if (out_idx) *out_idx = last;
    return 0;
}
