; test_sections.asm
; Test file with multiple sections to verify section data writing

section .text
  global _start

_start:
  mov rax, 42
  mov rbx, message
  ret

section .data
  message: .asciz "Hello, World!"
  number: .dword 12345

section .bss
  buffer: .space 256

section .rodata
  const_msg: .asciz "This is read-only"
  const_num: .dword 99999