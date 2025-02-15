START:
    MOV R1, 10       # Load 10 into R1
    MOV R2, [100]    # Load value from memory address 100 into R2
    MOV [200], R1    # Store R1 value into memory address 200
    ADD R1, 5        # Add 5 to R1
    JMP START        # Jump back to START
