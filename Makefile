CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -O2 -fPIC
INCDIR  := inc
SRCDIR  := src
OBJDIR  := obj
NAME    := woody_woodpacker

SRC := \
    $(SRCDIR)/main.c \
    $(SRCDIR)/elf_utils.c \
    $(SRCDIR)/packer.c

OBJ := $(SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

all: stub.bin $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

stub.bin: stub.s
	nasm -f bin $< -o $@

clean:
	rm -rf $(OBJDIR)

fclean: clean
	rm -f $(NAME) stub.bin woody

re: fclean all

.PHONY: all clean fclean re
