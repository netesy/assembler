START:
    MOV R1, 10       # Load 10 into R1
    SHL R1, 2        # Shift left R1 by 2 (R1 *= 4)
    SHR R1, 1        # Shift right R1 by 1 (R1 /= 2)
    MOV R2, 5        # Load 5 into R2
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
