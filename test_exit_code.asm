section .text
    global _start

_start:
    ; Exit with a specific code we can test
    mov rax, 60         ; sys_exit
    mov rdi, 123        ; exit code 123
    syscall