section .data
    msg db "Hello, Windows!", 0Ah
    len equ $ - msg

section .text
    global _start

_start:
    mov rax, 1      ; sys_write
    mov rdi, 1      ; stdout
    mov rsi, msg
    mov rdx, 16
    syscall

    ; Exit gracefully
    mov rax, 60     ; sys_exit
    mov rdi, 0
    syscall
