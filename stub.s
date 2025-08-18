BITS 64
default rel
%define KEYLEN 9

start:
anchor:
    push rdi
    push rsi
    push rdx
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg]
    mov rdx, msg_len
    syscall

    lea r11, [anchor]
    mov r8,  [delta_to_enc]
    add r8,  r11
    mov rcx, [enc_size]

    lea rsi, [key]
    xor r9d, r9d

.decrypt_loop:
    mov al, [r8]
    mov bl, [rsi + r9]
    xor al, bl
    mov [r8], al
    inc r8
    inc r9d
    cmp r9d, KEYLEN
    jb .no_wrap
    xor r9d, r9d
.no_wrap:
    dec rcx
    jnz .decrypt_loop

    pop rdx
    pop rsi
    pop rdi
    mov rax, [delta_to_entry]
    add rax, r11
    jmp rax

    align 8
delta_to_enc:      dq 0x1111111122222222
enc_size:          dq 0x3333333344444444
key_tag:           db 'K','E','Y','!'
key:               times KEYLEN db 0
    align 8
delta_to_entry:    dq 0x7777777788888888
msg: db "...WOODY...", 10
msg_len equ $ - msg
