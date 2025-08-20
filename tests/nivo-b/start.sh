ASSEMBLER=../../assembler
LINKER=../../linker
EMULATOR=../../emulator

${ASSEMBLER} -o main.o main.s
${ASSEMBLER} -o handler.o handler.s
${ASSEMBLER} -o isr_terminal.o isr_terminal.s
${ASSEMBLER} -o isr_timer.o isr_timer.s
${LINKER} -relocatable \
  -o isr_lib.hex \
  isr_timer.o isr_terminal.o
${LINKER} -hex \
  -place=my_code@0x40000000 \
  -place=isr@0x60000000 \
  -o program.hex \
  main.o isr_lib.hex.o handler.o
${EMULATOR} program.hex
