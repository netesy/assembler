; test.asm
section .text
    global _start

_start:
    ; sys_exit(0)
    mov rax, 60     ; exit
    mov rdi, 0
    syscall
