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
	
	phdr[load_index].p_filesz += 100;
   	phdr[load_index].p_memsz += 100;
   	
   	phdr[load_index].p_flags |= PF_W;  

	Elf64_Off text_offset;
	Elf64_Xword text_size;
	
	if (find_text_section(fd, &text_offset, &text_size) == 0) 
	{
		Elf64_Off stub_file_offset = phdr[load_index].p_offset + phdr[load_index].p_filesz - 100;
		Elf64_Addr stub_vaddr = phdr[load_index].p_vaddr + phdr[load_index].p_filesz - 100;
		
		unsigned char *text_data = (unsigned char*)data + text_offset;
		encrypt(text_data, text_size);
		
		unsigned char stub_code[] = 
		{
			0x50,                                     // push rax
			0x51,                                     // push rcx
			0x52,                                     // push rdx
			0x53,                                     // push rbx
			
			0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, // lea rax, [rip + text_offset] (7 bytes)
			
			0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, // mov rcx, text_size (7 bytes)
			
			0x80, 0x28, 0x0f,                         // sub byte ptr [rax], 15 (3 bytes)
			0x48, 0xff, 0xc0,                         // inc rax (3 bytes)
			0x48, 0xff, 0xc9,                         // dec rcx (3 bytes)
			0x75, 0xf5,                               // jnz -11 (loop back to sub) (2 bytes)
			
			0x5b,                                     // pop rbx
			0x5a,                                     // pop rdx
			0x59,                                     // pop rcx
			0x58,                                     // pop rax
			
			0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, // lea rax, [rip + original_entry_offset] (7 bytes)
			0xff, 0xe0                                 // jmp rax (2 bytes)
		};
		
		Elf64_Addr original_entry = obj->e_entry;
		
		obj->e_entry = stub_vaddr;
		Elf64_Addr text_vaddr = 0x1060;
		int32_t text_rip_offset = (int32_t)(text_vaddr - (stub_vaddr + 11));
		int32_t entry_rip_offset = (int32_t)(original_entry - (stub_vaddr + sizeof(stub_code) - 2));
		
		printf("Stub vaddr: 0x%lx\n", stub_vaddr);
		printf("Text vaddr: 0x%lx\n", text_vaddr);
		printf("Text size: 0x%lx (%lu)\n", text_size, text_size);
		printf("Original entry: 0x%lx\n", original_entry);
		printf("Text RIP offset: 0x%x\n", text_rip_offset);
		printf("Entry RIP offset: 0x%x\n", entry_rip_offset);
		printf("Stub size: %lu\n", sizeof(stub_code));
		
		*(int32_t*)(stub_code + 7) = text_rip_offset;           
		*(uint32_t*)(stub_code + 14) = (uint32_t)text_size;     
		*(int32_t*)(stub_code + 36) = entry_rip_offset;         
		
		int temp_fd = open("temp_packed", O_RDWR | O_CREAT | O_TRUNC, 0755);
		write(temp_fd, data, file_size);
		close(temp_fd);
		
		temp_fd = open("temp_packed", O_RDONLY);
		newelf(temp_fd, "packed_test", stub_code, sizeof(stub_code), stub_file_offset);
		close(temp_fd);
		unlink("temp_packed");
	}
	
	return 0;
}



void newelf(int fd, char *str, unsigned char *code, size_t code_size, Elf64_Off offset)
{
	int wr_fd;
	struct stat st;
	void *data;
	
	fstat(fd, &st);
	data = malloc(st.st_size);
	lseek(fd, 0, SEEK_SET);
	read(fd, data, st.st_size);
	
	wr_fd = open(str, O_RDWR | O_CREAT | O_TRUNC, 0755);
	
	write(wr_fd, data, st.st_size);
	
	lseek(wr_fd, offset, SEEK_SET);
	write(wr_fd, code, code_size);
	
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
	lseek(wr_fd, 0, SEEK_SET);
	write(wr_fd, ehdr, sizeof(Elf64_Ehdr));
	
	Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);
	lseek(wr_fd, ehdr->e_phoff, SEEK_SET);
	write(wr_fd, phdr, ehdr->e_phnum * sizeof(Elf64_Phdr));
	
	free(data);
	close(wr_fd);
}

