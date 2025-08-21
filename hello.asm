section .data
    hello db "Hello, world!", 13, 10
    hello_len equ $ - hello

section .text
    global _start

_start:
    ; sys_write
    mov rax, 1
    mov rdi, 1
    mov rsi, hello
    mov rdx, hello_len
    syscall

    ; sys_exit
    mov rax, 60
    mov rdi, 0
    syscall
