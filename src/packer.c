#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "woody.h"

#define SIG_DELTA_ENC  0x1111111122222222ULL
#define SIG_ENC_SIZE   0x3333333344444444ULL
#define SIG_DELTA_ENT  0x7777777788888888ULL
static const unsigned char SIG_KEY_TAG[4] = {'K','E','Y','!'};

static unsigned char* find_pattern(unsigned char *hay, size_t hay_len,
                                   const void *needle, size_t nlen) {
    if (nlen == 0 || hay_len < nlen) return NULL;
    const unsigned char *nd = (const unsigned char*)needle;
    for (size_t i = 0; i + nlen <= hay_len; ++i) {
        if (memcmp(hay + i, nd, nlen) == 0) return hay + i;
    }
    return NULL;
}

static int read_file(const char *path, unsigned char **out, size_t *outlen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t sz; if (x_get_file_size(fd, &sz) < 0) { close(fd); return -1; }
    unsigned char *buf = (unsigned char*)malloc(sz);
    if (!buf) { close(fd); return -1; }
    ssize_t r = read(fd, buf, sz);
    close(fd);
    if (r != (ssize_t)sz) { free(buf); return -1; }
    *out = buf; *outlen = sz; return 0;
}

static int get_random_bytes(unsigned char *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, n);
    close(fd);
    return (r == (ssize_t)n) ? 0 : -1;
}

int pack_buffer(const unsigned char *in, size_t in_size, const char *out_path) {
    if (elf_basic_checks(in, in_size) != 0) return -1;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)in;
    Elf64_Phdr exec_ph; int exec_idx;
    Elf64_Phdr last_ph; int last_idx;
    if (elf_find_exec_segment(in, &exec_ph, &exec_idx) != 0) return -1;
    if (elf_find_last_load_segment(in, &last_ph, &last_idx) != 0) return -1;

    Elf64_Off exec_file_off = exec_ph.p_offset;
    Elf64_Addr exec_vaddr   = exec_ph.p_vaddr;
    Elf64_Xword exec_fsz    = exec_ph.p_filesz;

    if (eh->e_entry < exec_vaddr || eh->e_entry >= exec_vaddr + exec_fsz) return -1;

    Elf64_Off enc_off  = exec_file_off + (eh->e_entry - exec_vaddr);
    Elf64_Xword enc_sz = exec_fsz - (eh->e_entry - exec_vaddr);
    if (enc_off + enc_sz > in_size || enc_sz == 0) return -1;

    unsigned char *stub = NULL; size_t stub_len = 0;
    if (read_file("stub.bin", &stub, &stub_len) != 0) return -1;

    unsigned char *work = (unsigned char*)malloc(in_size);
    if (!work) { free(stub); return -1; }
    memcpy(work, in, in_size);

    unsigned char key[KEY_LEN];
    if (get_random_bytes(key, KEY_LEN) != 0) {
        for (size_t i = 0; i < KEY_LEN; ++i) key[i] = 0x5A;
    }

    dprintf(1, "key_value: ");
    for (size_t i = 0; i < KEY_LEN; ++i) dprintf(1, "%02X", key[i]);
    dprintf(1, "\n");

    for (Elf64_Xword i = 0; i < enc_sz; ++i)
        work[enc_off + i] ^= key[i % KEY_LEN];

    Elf64_Ehdr *oh = (Elf64_Ehdr*)work;
    Elf64_Phdr *oph = (Elf64_Phdr*)(work + oh->e_phoff);
    Elf64_Phdr *o_exec = &oph[exec_idx];
    Elf64_Phdr *o_last = &oph[last_idx];

    Elf64_Off  stub_file_off = o_last->p_offset + o_last->p_filesz;
    Elf64_Addr stub_vaddr    = o_last->p_vaddr  + o_last->p_filesz;

    o_exec->p_flags |= PF_W | PF_R | PF_X;
    o_last->p_flags |= PF_W | PF_R | PF_X;
    o_last->p_filesz += stub_len;
    o_last->p_memsz  += stub_len;

    Elf64_Addr orig_entry = oh->e_entry;
    oh->e_entry = stub_vaddr;

    int64_t delta_to_enc = (int64_t)(orig_entry - stub_vaddr);
    int64_t delta_to_ent = (int64_t)(orig_entry - stub_vaddr);

    unsigned char *p;

    uint64_t sig_delta = SIG_DELTA_ENC;
    p = find_pattern(stub, stub_len, &sig_delta, sizeof(sig_delta));
    if (!p) { free(stub); free(work); return -1; }
    memcpy(p, &delta_to_enc, sizeof(delta_to_enc));

    uint64_t sig_size = SIG_ENC_SIZE;
    p = find_pattern(stub, stub_len, &sig_size, sizeof(sig_size));
    if (!p) { free(stub); free(work); return -1; }
    memcpy(p, &enc_sz, sizeof(enc_sz));

    p = find_pattern(stub, stub_len, SIG_KEY_TAG, sizeof(SIG_KEY_TAG));
    if (!p || (size_t)(p - stub + sizeof(SIG_KEY_TAG) + KEY_LEN) > stub_len) {
        free(stub); free(work); return -1;
    }
    for (size_t i = 0; i < KEY_LEN; ++i)
        stub[(p - stub) + sizeof(SIG_KEY_TAG) + i] = key[i];

    uint64_t sig_ent = SIG_DELTA_ENT;
    p = find_pattern(stub, stub_len, &sig_ent, sizeof(sig_ent));
    if (!p) { free(stub); free(work); return -1; }
    memcpy(p, &delta_to_ent, sizeof(delta_to_ent));

    if (oh->e_shoff != 0 && oh->e_shnum > 0) {
        Elf64_Off old_shoff = oh->e_shoff;
        size_t shdr_tbl_sz = (size_t)oh->e_shnum * sizeof(Elf64_Shdr);
        if (old_shoff + (Elf64_Off)shdr_tbl_sz <= (Elf64_Off)in_size) {
            Elf64_Shdr *sh = (Elf64_Shdr *)(work + old_shoff);
            for (int i = 0; i < oh->e_shnum; ++i) {
                if (sh[i].sh_offset >= stub_file_off) {
                    sh[i].sh_offset += stub_len;
                }
            }
            if (old_shoff >= stub_file_off) {
                oh->e_shoff = old_shoff + stub_len;
            }
        } else {
            oh->e_shoff = 0;
            oh->e_shnum = 0;
            oh->e_shstrndx = SHN_UNDEF;
        }
    }

    int wfd = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (wfd < 0) { free(stub); free(work); return -1; }

    size_t head = in_size;
    if (stub_file_off <= in_size) head = stub_file_off;

    if (write(wfd, work, head) != (ssize_t)head) { close(wfd); free(stub); free(work); return -1; }

    if (stub_file_off > in_size) {
        size_t pad = stub_file_off - in_size;
        unsigned char *zeros = (unsigned char*)calloc(1, pad);
        if (!zeros) { close(wfd); free(stub); free(work); return -1; }
        if (write(wfd, zeros, pad) != (ssize_t)pad) { free(zeros); close(wfd); free(stub); free(work); return -1; }
        free(zeros);
    }

    if (write(wfd, stub, stub_len) != (ssize_t)stub_len) { close(wfd); free(stub); free(work); return -1; }

    if (stub_file_off <= in_size) {
        size_t tail_len = in_size - head;
        if (write(wfd, work + head, tail_len) != (ssize_t)tail_len) { close(wfd); free(stub); free(work); return -1; }
    }

    close(wfd);
    free(stub);
    free(work);
    return 0;
}
