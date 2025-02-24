.data
message "Hello, World!\n"   # String data with automatic length calculation

.text
_start:                     # Entry point label
    # Write syscall
    MOV R0, 1              # file descriptor (stdout)
    MOV R1, message        # message address
    MOV R2, [message_len]  # message length (automatically calculated)
    MOV R3, 1              # syscall number (sys_write)

    # Exit syscall
    MOV R0, 0              # exit code 0
    MOV R3, 60             # syscall number (sys_exit)
