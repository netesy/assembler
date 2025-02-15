START:
    MOV R1, 10       # Load 10 into R1
    MOV R2, 5        # Load 5 into R2
    AND R1, R2       # Bitwise AND between R1 and R2
    OR  R1, R2       # Bitwise OR
    XOR R1, R2       # Bitwise XOR
    NOT R1           # Bitwise NOT on R1
    CMP R1, R2       # Compare R1 and R2
    JG GREATER       # Jump if R1 > R2
    MOV R3, 0        # Default case

GREATER:
    MOV R3, 1        # R3 = 1 if R1 > R2
    CALL FUNC        # Call function FUNC
    JMP START        # Loop forever

FUNC:
    PUSH R1          # Save R1
    ADD R1, 5        # Modify R1
    POP R1           # Restore R1
    RET              # Return to caller
