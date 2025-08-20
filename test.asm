; test.asm
section .data
    msg db 'Hello, Windows!', 0ah
    len equ $ - msg

section .text
    global _start

_start:
    ; sys_write(1, msg, len)
    mov rax, 1      ; write
    mov rdi, 1      ; stdout
    mov rsi, msg
    mov rdx, len
    syscall

    ; sys_exit(0)
    mov rax, 60     ; exit
    mov rdi, 0
    syscall
