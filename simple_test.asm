section .data
    my_var dq 0

section .text
    global _start
_start:
    mov [my_var], rax
    ret
