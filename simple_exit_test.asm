section .text
    global _start

_start:
    ; Simple exit with code 42
    mov rax, 60         ; sys_exit
    mov rdi, 42         ; exit code
    syscall