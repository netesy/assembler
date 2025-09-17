.section .text
.global _start

_start:
  mov w8, #93   ; syscall number for exit on aarch64
  mov w0, #42   ; exit code 42
  svc #0        ; make the syscall
