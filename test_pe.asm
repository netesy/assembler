; test_pe.asm
; A simple program to test PE generation and imports.

extrn ExitProcess:PROC

section .text
  global _start

_start:
  sub rsp, 40      ; Shadow space for the call
  xor ecx, ecx      ; Exit code 0
  call ExitProcess  ; Call the imported function
  add rsp, 40      ; Clean up stack
