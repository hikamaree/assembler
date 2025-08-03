.equ foo, 0xABC + value
.section text
	jmp 0x100
	jmp 0x12345678
	jmp value
	jmp [%r4 + 8]
	jmp [%r5 + foo]
	
	beq %r1, %r2, 0x200
	beq %r1, %r2, 0xABCDEF01
	beq %r1, %r2, value
	beq %r1, %r2, [%r6 + 16]
	beq %r1, %r2, [%r6 + foo]
	
	bne %r3, %r4, 0x300
	bne %r3, %r4, 0xDEADBEEF
	bne %r3, %r4, value
	bne %r3, %r4, [%r7 + 32]
	
	bgt %r8, %r9, 0x400
	bgt %r8, %r9, 0xCAFEBABE
	bgt %r8, %r9, value
	bgt %r8, %r9, [%r2 + 64]
	
	call 0x500
	call 0xFEEDFACE
	call value
	call [%r3 + 4]
    ld $0x88888888, %r1
    add %r1, %r2
value:
    ld $value1, %r2
    ld value, %r3
    st %r1, value
    st %r2, 0x12345678
    ret

.section data
.word 0x69696969, 0x74747474
value1:
.word 0xFFFFFFFF
