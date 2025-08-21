section .text
  global _start

_start:
  mov rsi, 0
  mov rax, 1
  mov rdi, 1
  mov rdx, 16
  syscall

  ret
