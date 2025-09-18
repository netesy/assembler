section .data
    msg db "Hello from custom assembler!", 13, 10, 0
    msg_len equ $ - msg

section .text
    global _start

_start:
    ; Write message to stdout
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    mov rsi, msg        ; message
    mov rdx, msg_len    ; length
    syscall

    ; Exit with code 42
    mov rax, 60         ; sys_exit
    mov rdi, 42         ; exit code
    syscall