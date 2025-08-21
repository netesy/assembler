section .data
  hello db "Hello, Windows!", 10

section .text
  global _start

_start:
  ; Write "Hello, Windows!" to stdout
  mov rax, 1         ; syscall number for sys_write
  mov rdi, 1         ; file descriptor for stdout
  mov rsi, hello     ; message to write
  mov rdx, 16        ; message length
  syscall

  ; Exit
  ret
