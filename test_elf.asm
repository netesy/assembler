.section .bss
  my_var: .resb 1
  my_other_var: .resb 10

.section .text
  global _start

_start:
  mov rax, 60
  mov rdi, 42
  syscall
