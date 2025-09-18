.section .text
.globl _start

_start:
    # Simple calculation: 10 + 5 + 7 = 22
    movq $10, %rax
    movq $5, %rbx
    addq %rbx, %rax
    addq $7, %rax
    
    # Exit with result using Windows API
    movq %rax, %rcx    # Move result to rcx (first parameter for Windows calling convention)
    call ExitProcess

.section .rdata
.extern ExitProcess