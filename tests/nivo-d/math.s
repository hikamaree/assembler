# file: math.s

.global mathNot, mathAnd, mathOr, mathXor, mathShl, mathShr, mathMul

.section math
mathNot:
    ld [%sp + 0x04], %r1
    not %r1 # r1 used for the result
    ret

mathAnd:
    push %r2
    ld [%sp + 0x08], %r1
    ld [%sp + 0x0C], %r2
    and %r2, %r1 # r1 used for the result
    pop %r2
    ret

mathOr:
    push %r2
    ld [%sp + 0x08], %r1
    ld [%sp + 0x0C], %r2
    or %r2, %r1 # r1 used for the result
    pop %r2
    ret

mathXor:
    push %r2
    ld [%sp + 0x08], %r1
    ld [%sp + 0x0C], %r2
    xor %r2, %r1 # r1 used for the result
    pop %r2
    ret

mathShl:
    push %r2
    ld [%sp + 0x08], %r1
    ld [%sp + 0x0C], %r2
    shl %r2, %r1 # r1 used for the result
    pop %r2
    ret

mathShr:
    push %r2
    ld [%sp + 0x08], %r1
    ld [%sp + 0x0C], %r2
    shr %r2, %r1 # r1 used for the result
    pop %r2
    ret

mathMul:
    push %r2
    ld [%sp + 0x08], %r1
    ld [%sp + 0x0C], %r2
    xchg %r1, %r2
    bgt %r1, %r2, bgt_test
    mul %r1, %r1
bgt_test:
    mul %r2, %r1 # r1 used for the result
    pop %r2
    ret

.end
