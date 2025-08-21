section .text
    global _start

_start:
    ; mmap
    mov rax, 9
    mov rdi, 0
    mov rsi, 4096
    mov rdx, 3
    mov r10, 34
    syscall

    ; exit
    mov rax, 60
    mov rdi, 0
    syscall
