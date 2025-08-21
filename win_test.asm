extern ExitProcess

section .text
    global main

main:
    mov     rax, 10
    mov     rbx, 5
    add     rax, rbx
    add     rax, 7
    mov     rcx, rax
    call    ExitProcess
