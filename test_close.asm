section .text
    global _start

_start:
    ; close
    mov rax, 3
    mov rdi, 5 ; some dummy file descriptor
    syscall

    ; exit
    mov rax, 60
    mov rdi, 0
    syscall
