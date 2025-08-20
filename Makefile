CXX := gcc
CXXFLAGS := -std=c11 -Wall -Wextra -Wno-unused-function -D_POSIX_C_SOURCE=200809L -I./src
BUILD_DIR := build
SRC_DIR := src
MICS_DIR := mics

ASSEMBLER_TARGET := assembler
LINKER_TARGET := linker
EMULATOR_TARGET := emulator

ASSEMBLER_SRCS := $(SRC_DIR)/assembler.c
LINKER_SRCS := $(SRC_DIR)/linker.c
EMULATOR_SRC := $(SRC_DIR)/emulator.c

FLEX_SRC := $(MICS_DIR)/assembler.l
BISON_SRC := $(MICS_DIR)/assembler.y

BISON_C := $(BUILD_DIR)/assembler.tab.c
BISON_H := $(BUILD_DIR)/assembler.tab.h
FLEX_C := $(BUILD_DIR)/lex.yy.c

ASSEMBLER_OBJS := $(BUILD_DIR)/assembler.o $(BUILD_DIR)/assembler.tab.o $(BUILD_DIR)/lex.yy.o
LINKER_OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(LINKER_SRCS))
EMULATOR_OBJ := $(BUILD_DIR)/emulator.o

.PHONY: all clean

all: $(ASSEMBLER_TARGET) $(LINKER_TARGET) $(EMULATOR_TARGET)

# Flex lexer generation
$(FLEX_C): $(FLEX_SRC) $(BISON_H)
	@mkdir -p $(BUILD_DIR)
	flex -o$(FLEX_C) $(FLEX_SRC)

# Bison parser generation
$(BISON_C) $(BISON_H): $(BISON_SRC)
	@mkdir -p $(BUILD_DIR)
	bison -d -o $(BISON_C) $(BISON_SRC)

# Compile generated Bison parser
$(BUILD_DIR)/assembler.tab.o: $(BISON_C)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile generated Flex lexer
$(BUILD_DIR)/lex.yy.o: $(FLEX_C)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile assembler.c
$(BUILD_DIR)/assembler.o: $(SRC_DIR)/assembler.c
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile emulator.c
$(EMULATOR_OBJ): $(EMULATOR_SRC)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile other .c files in src directory to .o (like linker.c)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link assembler executable
$(ASSEMBLER_TARGET): $(ASSEMBLER_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Link linker executable
$(LINKER_TARGET): $(LINKER_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Link emulator executable
$(EMULATOR_TARGET): $(EMULATOR_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -rf $(BUILD_DIR) $(ASSEMBLER_TARGET) $(LINKER_TARGET) $(EMULATOR_TARGET)
