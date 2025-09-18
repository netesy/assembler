.section .text
.globl _start

_start:
    # Simple calculation: 10 + 5 + 7 = 22
    movq $10, %rax
    movq $5, %rbx
    addq %rbx, %rax
    addq $7, %rax
    
    # Exit with result
    movq %rax, %rdi
    movq $60, %rax
    syscall