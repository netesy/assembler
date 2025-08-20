.section .data
message: .asciz "Hello, relocatable world!\n"

.section .text
.global main
.extern printf

main:
    ; A proper function prologue
    push rbp
    mov rbp, rsp

    ; Call printf(message)
    ; In the x86-64 calling convention, the first argument goes in RDI
    mov rdi, message
    call printf

    ; A proper function epilogue
    mov rsp, rbp
    pop rbp

    ; Return 0 from main
    mov rax, 0
    ret
