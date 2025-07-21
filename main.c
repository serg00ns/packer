#include <sys/stat.h>
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

int find_text_section(int fd, Elf64_Off *text_offset, Elf64_Xword *text_size) 
{
    Elf64_Ehdr ehdr;

    lseek(fd, 0, SEEK_SET);
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) 
	{
        perror("read ehdr");
        return -1;
    }

    if (ehdr.e_shstrndx == SHN_UNDEF) 
	{
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
	Elf64_Ehdr *obj;
	Elf64_Phdr *phdr;
	struct stat st;
	long file_size;
	int fd;
	void *data;
	int load_index = 0;

	
	fd = open("./test", O_RDONLY);
	stat("./test", &st);
	file_size = st.st_size;
	data = malloc(file_size + 4096);
	memset(data, 0, file_size + 4096);
	read(fd, data, file_size);
	obj = (Elf64_Ehdr *)data;
	phdr = (Elf64_Phdr *)(data + obj->e_phoff);
	for (size_t i = 0; i < obj->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) 
		{
        	load_index = i;
        	break;
    	}
	}
	printf("index = %d\n", load_index);
	
	phdr[load_index].p_flsz += 100;
   	phdr[load_index].p_memsz += 100;

	// put stub end of the text section and redirect O_EP to stub EP then stub to O_EP
	//
	//
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
	lseek(wr_fd, 0, SEEK_SET);
	put_shellcode(wr_fd);
	close(wr_fd);
}

