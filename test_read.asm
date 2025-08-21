section .bss
    buffer resb 256

section .text
    global _start

_start:
    ; read
    mov rax, 0
    mov rdi, 0 ; stdin
    mov rsi, buffer
    mov rdx, 256
    syscall

    ; exit
    mov rax, 60
    mov rdi, 0
    syscall
