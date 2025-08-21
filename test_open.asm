section .data
    filename db "test.txt", 0

section .text
    global _start

_start:
    ; open
    mov rax, 2
    mov rdi, filename
    syscall

    ; exit
    mov rax, 60
    mov rdi, 0
    syscall
