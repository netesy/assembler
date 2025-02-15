START:
    MOV R1, 10       # Load 10 into R1
    CALL FUNC        # Call function FUNC
    MOV R2, [100]    # Load value from memory address 100 into R2
    JMP START        # Loop forever

FUNC:
    PUSH R1          # Save R1
    ADD R1, 5        # Modify R1
    POP R1           # Restore R1
    RET              # Return to caller
