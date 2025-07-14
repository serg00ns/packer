#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

void newelf(int fd, char *str, unsigned char *code, size_t code_size, Elf64_Xword offset);

void encrypt(unsigned char *buf, size_t size)
{
	int i = 0;

	while (i < size)
	{
		buf[i] += 15; 
		i++;
	}
}
int find_text_section(int fd, Elf64_Off *text_offset, Elf64_Xword *text_size) {
    Elf64_Ehdr ehdr;

    lseek(fd, 0, SEEK_SET);
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read ehdr");
        return -1;
    }

    if (ehdr.e_shstrndx == SHN_UNDEF) {
        return -1;
    }

    Elf64_Shdr shstr_shdr;
    lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    if (read(fd, &shstr_shdr, sizeof(shstr_shdr)) != sizeof(shstr_shdr)) {
        perror("read shstrtab header");
        return -1;
    }

    char *shstrtab = malloc(shstr_shdr.sh_size);
    if (!shstrtab) {
        perror("malloc");
        return -1;
    }

    lseek(fd, shstr_shdr.sh_offset, SEEK_SET);
    if (read(fd, shstrtab, shstr_shdr.sh_size) != (ssize_t)shstr_shdr.sh_size) {
        perror("read shstrtab");
        free(shstrtab);
        return -1;
    }

    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        lseek(fd, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
        if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
            perror("read shdr");
            break;
        }

        const char *sec_name = shstrtab + shdr.sh_name;
        if (strcmp(sec_name, ".text") == 0) {
            *text_offset = shdr.sh_offset;
            *text_size   = shdr.sh_size;
            free(shstrtab);
            return 0;
        }
    }

    free(shstrtab);
    return -1;
}


int main()
{
	Elf64_Ehdr obj;
	
	int fd = open("./a.out", O_RDONLY);

	read(fd, &obj, sizeof(obj));
	printf("ELF type : %u\n", obj.e_type);
	printf("ELF entry point : 0x%lx\n", obj.e_entry);
	
	Elf64_Off text_off;
    Elf64_Xword text_size;
    if (find_text_section(fd, &text_off, &text_size) == 0) {
        printf(".text offset: 0x%lx\n", text_off);
        printf(".text size  : 0x%lx\n", text_size);
    }
	unsigned char *code;
	code = malloc(text_size);
	lseek(fd, text_off, SEEK_SET);
	read(fd, code, text_size);	
	encrypt(code, text_size);
	add_stub()
	newelf(fd, "woody_exe", code, text_size, text_off);
	close(fd);
	return 0;
}

void newelf(int fd, char *str, unsigned char *code, size_t code_size, Elf64_Off offset)
{
	int wr_fd;
	size_t  f_size;

	wr_fd = open(str, O_RDWR | O_CREAT | O_TRUNC, 0755 );
	
	lseek(fd, 0, SEEK_SET);
	char buf[1];
	while(read(fd, buf, 1))
	{
		write(wr_fd, buf, 1);
	}
	lseek(wr_fd, offset, SEEK_SET);
	write(wr_fd, code, code_size);
	close(wr_fd);
}




