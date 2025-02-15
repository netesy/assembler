START:
    MOV R1, 0x8F     # Load 0x8F into R1 (binary 10001111)
    BT R1, 3         # Test bit 3 of R1
    BTS R1, 2        # Set bit 2 of R1 (binary 10011111)
    BTR R1, 0        # Reset bit 0 of R1 (binary 10011110)
    MOV R2, [100]    # Move value at memory address 100 into R2
    MOV [200], R2    # Move value of R2 to memory address 200
    PUSH [300]       # Push value at memory address 300 onto stack
    POP [400]        # Pop value from stack into memory address 400
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
