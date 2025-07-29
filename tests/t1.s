.section text
#.word 5
#.word 10
#.skip 8
.global label

label:
    halt
    int
    iret
labela1:
    ret
    jmp labela1
    push %r1
    pop %r2
    xchg %r3, %r4
    add %r5, %r6
    sub %r7, %r8
    mul %r1, %r2
    div %r3, %r4
    not %r5
    and %r6, %r7
    or %r8, %r1
    xor %r2, %r3
    shl %r4, %r5
    shr %r6, %r7
    ld label, %r1
    st %r1, label
    csrrd %csr0, %r2
    csrwr %r3, %csr1
.end

