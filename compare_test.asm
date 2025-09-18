section .text
global _start

_start:
    ; Simple calculation: 10 + 5 + 7 = 22
    mov rax, 10
    mov rbx, 5
    add rax, rbx
    add rax, 7
    
    ; Exit with result
    mov rdi, rax
    mov rax, 60
    syscall