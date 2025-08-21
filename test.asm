section .text
  global _start

_start:
  mov rax, 10      ; Start with 10
  mov rbx, 5       ; Load 5 into another register
  add rax, rbx     ; Add them, rax = 15
  add rax, 7       ; Add an immediate value, rax = 22
  mov rdi, rax     ; Move the result to rdi for the exit code
  mov rax, 60      ; syscall number for exit
  syscall
