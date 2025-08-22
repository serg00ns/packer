#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <errno.h>
#include "woody.h"

static int precheck_elf64(int fd) {
    Elf64_Ehdr eh;
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    ssize_t r = read(fd, &eh, sizeof(eh));
    if (r != (ssize_t)sizeof(eh)) return -1;

    if (memcmp(eh.e_ident, ELFMAG, (size_t)SELFMAG) != 0) return -1;
    if (eh.e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (eh.e_ident[EI_DATA]  != ELFDATA2LSB) return -1;
    if (eh.e_machine != EM_X86_64) return -1;

    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        dprintf(2, "usage: %s <elf64-x86_64>\n", argv[0]);
        return 1;
    }

    const char *in_path = argv[1];
    int fd = open(in_path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            dprintf(2, "error: invalid path\n");
        } else if (errno == EACCES || errno == EPERM) {
            dprintf(2, "error: invalid permission\n");
        } else {
            dprintf(2, "error: invalid file\n");
        }
        return 1;
    }

    size_t sz_check = 0;
    if (x_get_file_size(fd, &sz_check) < 0 || sz_check == 0) {
        dprintf(2, "error: invalid file\n");
        close(fd);
        return 1;
    }

    if (precheck_elf64(fd) != 0) {
        dprintf(2, "error: invalid file\n");
        close(fd);
        return 1;
    }

    size_t fsize = 0;
    if (x_get_file_size(fd, &fsize) < 0) {
        dprintf(2, "error: invalid file\n");
        close(fd);
        return 1;
    }

    void *map = x_mmap_ro(fd, fsize);
    if (!map) {
        dprintf(2, "error: invalid file\n");
        close(fd);
        return 1;
    }
    close(fd);

    if (pack_buffer((const unsigned char*)map, fsize, OUT_FILE) != 0) {
        dprintf(2, "error: invalid file\n");
        return 1;
    }
    return 0;
}
