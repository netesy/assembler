; test_edge_cases.asm
; Test edge cases for section data writing

section .text
  global _start

_start:
  nop
  nop
  nop

section .data
  ; Small data section
  byte_val: .byte 0xFF

section .bss
  ; Uninitialized section
  large_buffer: .space 4096

section .rodata
  ; Read-only data
  version: .asciz "v1.0"