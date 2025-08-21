section .data
    filename db "test.txt", 0
    buffer times 256 db 0

section .text
    global _start

_start:
    ; mmap
    mov rax, 9
    mov rdi, 0
    mov rsi, 4096
    mov rdx, 3
    mov r10, 34
    syscall

    ; open
    mov rax, 2
    mov rdi, filename
    syscall

    ; read
    mov rax, 0
    mov rdi, 5 ; assume fd from open
    mov rsi, buffer
    mov rdx, 256
    syscall

    ; close
    mov rax, 3
    mov rdi, 5 ; assume fd from open
    syscall

    ; exit
    mov rax, 60
    mov rdi, 0
    syscall
