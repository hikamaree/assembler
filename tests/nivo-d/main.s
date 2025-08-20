# file: main.s

.extern handler, mathNot, mathAnd, mathOr, mathXor, mathShl, mathShr, mathMul

.global my_start

.section my_data
value1:
.word 0
value2:
.word 0
value3:
.word 0
value4:
.word 0
value5:
.word 0
value6:
.word 0
value7:
.word 0
value8:
.word 0x69

.skip 100

value9:
.word d, 0x169, d

.equ c, a + b       # 0x4000
.equ t, c - a       # 0x3000
.equ b, a + 0x2000  # 0x3000
.equ d, g - a - 1   # 0xfffff000
.equ a, 0x1000      # 0x1000
.equ g, 1           # 1

.global value1, value2, value3, value4, value5, value6, value7, value8

.section my_code
my_start:
    ld $0xFFFFFEFE, %sp
    ld $handler, %r1
    csrwr %r1, %handler

    int # software interrupt

    ld $0xcafebabe, %r1
    push %r1
    call mathNot
    st %r1, value1

    ld $0xabcd, %r1
    push %r1
    ld $0xdcba, %r1
    push %r1
    call mathAnd
    st %r1, value2

    ld $7, %r1
    push %r1
    ld $11, %r1
    push %r1
    call mathOr
    st %r1, value3

    ld $5, %r1
    push %r1
    ld $25, %r1
    push %r1
    call mathXor
    st %r1, value4

    ld $4, %r1
    push %r1
    ld $24, %r1
    push %r1
    call mathShl
    st %r1, value5

    ld $4, %r1
    push %r1
    ld $24, %r1
    push %r1
    call mathShr
    st %r1, value6

    ld $c, %r1
    push %r1
    ld $d, %r1
    push %r1
    call mathMul
    st %r1, value7

    ld value1, %r1
    ld value2, %r2
    ld value3, %r3
    ld value4, %r4
    ld value5, %r5
    ld value6, %r6
    ld value7, %r7
    ld value8, %r8
    ld $value9, %r9
    ld [%r9], %r10
    ld [%r9 + off], %r11
    ld [%r9 + off2], %r12

    halt

.equ off, 4
.equ off2, off + off

.end
