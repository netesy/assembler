.section .data
msg:
    .ascii "Hello from GNU assembler!\r\n"
    .byte 0
msg_len = . - msg

.section .text
.globl _start

_start:
    # Write message using Windows API
    subq $40, %rsp          # Shadow space
    
    # GetStdHandle(STD_OUTPUT_HANDLE)
    movq $-11, %rcx         # STD_OUTPUT_HANDLE
    call GetStdHandle
    
    # WriteFile(handle, msg, len, &written, NULL)
    movq %rax, %rcx         # handle
    leaq msg(%rip), %rdx    # message
    movq $msg_len, %r8      # length
    leaq 32(%rsp), %r9      # &written
    movq $0, 40(%rsp)       # overlapped = NULL
    call WriteFile
    
    addq $40, %rsp          # Clean up stack
    
    # Exit with code 42
    movq $42, %rcx
    call ExitProcess

.extern GetStdHandle
.extern WriteFile
.extern ExitProcess