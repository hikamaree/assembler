#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <string_list.h>
#include <errno.h>

#include "elf_format.h"

extern int yyparse(void);
extern FILE *yyin;

char* g_current_yytext = NULL;

void assembler_handle_label(const char* label);
void assembler_handle_section(const char* section_name);
void assembler_handle_word(const StringList* words);
void assembler_handle_skip(int size);
void assembler_handle_global(const StringList* symbols);
void assembler_handle_extern(const StringList* symbols);
void assembler_handle_end(void);
void assembler_handle_instruction(const char* mnemonic, const StringList* operands);

#define CHECK_REG(op, idx) \
    if ((op).type != OPERAND_REG) { \
        fprintf(stderr, "Operand %d must be a register\n", idx); \
        exit(EXIT_FAILURE); \
    }

#define CHECK_LITERAL_OR_SYMBOL(op, idx) \
    if ((op).type != OPERAND_LITERAL && (op).type != OPERAND_SYMBOL) { \
        fprintf(stderr, "Operand %d must be a literal or symbol\n", idx); \
        exit(EXIT_FAILURE); \
    }

#define CHECK_CSR(op, idx) \
    if ((op).type != OPERAND_CSR) { \
        fprintf(stderr, "Operand %d must be a CSR\n", idx); \
        exit(EXIT_FAILURE); \
    }

typedef struct {
    int base_reg;
    int offset;
    char* offset_symbol;
} MemOperand;

typedef struct {
    bool end_encountered;
    char current_section[64];
} AssemblerState;

static AssemblerState state = {
    .end_encountered = false,
    .current_section = "default",
};

Relocation relocations[MAX_RELOCATIONS];
size_t reloc_count = 0;

static Symbol symbols[MAX_SYMBOLS];
static size_t symbol_count = 0;

Section sections[64];
int section_count = 0;

Section *get_section(const char *name) {
    for (int i = 0; i < section_count; i++) {
        if (strcmp(sections[i].name, name) == 0)
            return &sections[i];
    }
    Section *sec = &sections[section_count++];
    strncpy(sec->name, name, sizeof(sec->name)-1);
    sec->capacity = 1024;
    sec->data = malloc(sec->capacity);
    sec->size = 0;
    sec->base = 0;
    return sec;
}

void section_write_bytes(Section *sec, const void *buf, size_t len) {
    if (sec->size + len > sec->capacity) {
        sec->capacity = (sec->size + len) * 2;
        sec->data = realloc(sec->data, sec->capacity);
    }
    memcpy(sec->data + sec->size, buf, len);
    sec->size += len;
}

uint32_t parse_literal(const char* s) {
    return (uint32_t)strtoul(s, NULL, 0);
}

bool is_literal(const char* s) {
    if (!s || *s == '\0') return false;

    if (s[0] == '-' || isdigit((unsigned char)s[0])) {
        char *endptr;
        strtol(s, &endptr, 0);
        return (*endptr == '\0');
    }
    return false;
}

Symbol* find_symbol(const char* name) {
    for (size_t i = 0; i < symbol_count; i++) {
        if (strcmp(symbols[i].name, name) == 0) {
            return &symbols[i];
        }
    }
    return NULL;
}

Symbol* add_symbol(const char* name) {
    Symbol* sym = find_symbol(name);
    if (sym) return sym;

    if (symbol_count >= MAX_SYMBOLS) {
        fprintf(stderr, "Previše simbola!\n");
        exit(EXIT_FAILURE);
    }

    sym = &symbols[symbol_count++];
    sym->name = strdup(name);
    sym->offset = 0;
    sym->section = NULL;
    sym->defined = false;
    sym->global = false;
    sym->external = false;
    return sym;
}

int parse_register(const char *s) {
    if (!s || s[0] == '\0') return -1;
    if (strcmp(s, "pc") == 0) return 15;
    if (strcmp(s, "sp") == 0) return 14;

    int i = 0;
    if (s[i] == '%') i++;

    if (s[i] != 'r') return -1;
    i++;
    if (!isdigit((unsigned char)s[i])) return -1;
    char *endptr;
    long val = strtol(&s[i], &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > 15) return -1;
    return (int)val;
}

int parse_csr(const char *s) {
    if (strcmp(s, "csr0") == 0 || strcmp(s, "status") == 0) return 0;
    if (strcmp(s, "csr1") == 0 || strcmp(s, "handler") == 0) return 1;
    if (strcmp(s, "csr2") == 0 || strcmp(s, "cause") == 0) return 2;
    return -1;
}

void add_relocation(Section *sec, size_t offset, const char *symbol, RelocType type) {
    if (reloc_count >= MAX_RELOCATIONS) {
        fprintf(stderr, "Previše relokacija!\n");
        exit(1);
    }
    relocations[reloc_count].section = sec;
    relocations[reloc_count].offset = offset;
    relocations[reloc_count].size = 4;
    relocations[reloc_count].symbol = strdup(symbol);
    relocations[reloc_count].type = type;
    reloc_count++;
}

void add_operand_relocation(const Operand* op) {
    if (op->type == OPERAND_SYMBOL || (op->type == OPERAND_MEM && op->mem.offset_symbol)) {
        Section* sec = get_section(state.current_section);

        size_t reloc_offset = sec->size;

        const char* sym = (op->type == OPERAND_SYMBOL) ? op->symbol : op->mem.offset_symbol;
        add_relocation(sec, reloc_offset, sym, RELOC_ABS);
    }
}

void assembler_handle_label(const char* label) {
	Symbol* sym = add_symbol(label);
	if (sym->defined) {
		fprintf(stderr, "Error: symbol '%s' is already defined!\n", label);
		exit(EXIT_FAILURE);
	}

	sym->defined = true;
	sym->section = strdup(state.current_section);

	Section* sec = get_section(state.current_section);
	sym->offset = sec->size - 4;
}

void assembler_handle_section(const char* section_name) {
	strncpy(state.current_section, section_name, sizeof(state.current_section) - 1);
}

void assembler_handle_word(const StringList* words) {
	Section *sec = get_section(state.current_section);
	for (int i = 0; i < words->size; i++) {
		const char *w = words->data[i];
		uint32_t val = 0;
		if (is_literal(w)) {
			val = parse_literal(w);
		} else {
			val = 0;
			add_relocation(sec, sec->size, w, RELOC_ABS);
		}

		uint8_t be[4];
		be[0] = (val >> 24) & 0xFF;
		be[1] = (val >> 16) & 0xFF;
		be[2] = (val >> 8) & 0xFF;
		be[3] = val & 0xFF;

		section_write_bytes(sec, be, 4);
	}
}

void assembler_handle_skip(int size) {
	Section *sec = get_section(state.current_section);
	unsigned char zeros[256] = {0};

	while (size > 0) {
		int chunk = size > 256 ? 256 : size;
		section_write_bytes(sec, zeros, chunk);
		size -= chunk;
	}
}

void assembler_handle_global(const StringList* symbols) {
	for (int i = 0; i < symbols->size; i++) {
		Symbol* sym = add_symbol(symbols->data[i]);
		sym->global = true;
	}
}

void assembler_handle_extern(const StringList* symbols) {
	for (int i = 0; i < symbols->size; i++) {
		Symbol* sym = add_symbol(symbols->data[i]);
		sym->external = true;
	}
}

void assembler_handle_end(void) {
	state.end_encountered = true;
}

void assembler_handle_ascii(const char* str) {
    Section *sec = get_section(state.current_section);
    section_write_bytes(sec, (const unsigned char*)str, strlen(str));
}

static void emit(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
    uint8_t encoded[4] = { b0, b1, b2, b3 };
    Section* sec = get_section(state.current_section);
    section_write_bytes(sec, encoded, 4);
}

void emit_instruction(uint8_t oc, uint8_t mod, uint8_t regA, uint8_t regB, uint8_t regC, int16_t disp) {
	if (disp < 0 || disp > 4095) {
        fprintf(stderr, "Disp out of range: %d\n", disp);
        exit(1);
    }
    uint8_t disp_high = (disp >> 8) & 0x0F;
    uint8_t disp_low = disp & 0xFF;

    uint8_t byte1 = ((oc & 0x0F) << 4) | (mod & 0x0F);
    uint8_t byte2 = ((regA & 0x0F) << 4) | (regB & 0x0F);
    uint8_t byte3 = ((regC & 0x0F) << 4) | disp_high;
    uint8_t byte4 = disp_low;

    emit(byte1, byte2, byte3, byte4);
}

void assembler_handle_halt(void) {
    emit_instruction(0x0, 0x0, 0, 0, 0, 0);
}

void assembler_handle_int(void) {
    emit_instruction(0x1, 0x0, 0, 0, 0, 0);
}

void assembler_handle_iret(void) {
    emit_instruction(0x9, 0x6, 0, 14, 0, 8);
    emit_instruction(0x9, 0x3, 15, 14, 0, 8);
}

void assembler_handle_ret(void) {
    emit_instruction(0x9, 0x3, 15, 14, 0, 4);
}

void assembler_handle_push(const Operand* r) {
    CHECK_REG(*r, 1);
    emit_instruction(0x8, 0x1, 14, 0, r->reg, 0xFFC);
}

void assembler_handle_pop(const Operand* r) {
    CHECK_REG(*r, 1);
    emit_instruction(0x9, 0x3, r->reg, 14, 0, 4);
}

void assembler_handle_call(const Operand* op) {
    uint8_t mod = 0x0;
    uint8_t regA = 0;
    uint8_t regB = 0;
    uint8_t regC = 0;
    int16_t disp = 0;

    switch (op->type) {
        case OPERAND_SYMBOL:
            disp = 0;
            add_operand_relocation(op);
            break;
        case OPERAND_ADDR:
            disp = op->literal;
            break;
        case OPERAND_LITERAL:
            disp = op->literal;
            break;
        default:
            fprintf(stderr, "Invalid operand type for call\n");
            exit(1);
    }

    emit_instruction(0x2, mod, regA, regB, regC, disp);
}

void assembler_handle_jmp(const Operand* op) {
    uint8_t mod;
    uint8_t regA = 0, regB = 0, regC = 0;
    int16_t disp = 0;

    if (op->type == OPERAND_MEM) {
        regA = op->mem.base_reg;
        mod = 0x8;

        if (op->mem.offset_symbol) {
            disp = 0;
            add_operand_relocation(op);
        } else {
            disp = op->mem.offset;
        }
    } else {
        CHECK_LITERAL_OR_SYMBOL(*op, 1);
        regA = 0;
        mod = 0x0;
        disp = 0;
        add_operand_relocation(op);
    }

    emit_instruction(0x3, mod, regA, regB, regC, disp);
}

void assembler_handle_beq(const Operand* r1, const Operand* r2, const Operand* op) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    uint8_t mod;
    uint8_t regA = 0, regB = r1->reg, regC = r2->reg;
    int16_t disp = 0;

    if (op->type == OPERAND_MEM) {
        regA = op->mem.base_reg;
        mod = 0x9;

        if (op->mem.offset_symbol) {
            disp = 0;
            add_operand_relocation(op);
        } else {
            disp = op->mem.offset;
        }
    } else {
        CHECK_LITERAL_OR_SYMBOL(*op, 3);
        regA = r1->reg;
        mod = 0x1;
        disp = 0;
        add_operand_relocation(op);
    }

    emit_instruction(0x3, mod, regA, regB, regC, disp);
}

void assembler_handle_bne(const Operand* r1, const Operand* r2, const Operand* op) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    uint8_t mod;
    uint8_t regA = 0, regB = r1->reg, regC = r2->reg;
    int16_t disp = 0;

    if (op->type == OPERAND_MEM) {
        regA = op->mem.base_reg;
        mod = 0xA;

        if (op->mem.offset_symbol) {
            disp = 0;
            add_operand_relocation(op);
        } else {
            disp = op->mem.offset;
        }
    } else {
        CHECK_LITERAL_OR_SYMBOL(*op, 3);
        regA = r1->reg;
        mod = 0x2;
        disp = 0;
        add_operand_relocation(op);
    }

    emit_instruction(0x3, mod, regA, regB, regC, disp);
}

void assembler_handle_bgt(const Operand* r1, const Operand* r2, const Operand* op) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    uint8_t mod;
    uint8_t regA = 0, regB = r1->reg, regC = r2->reg;
    int16_t disp = 0;

    if (op->type == OPERAND_MEM) {
        regA = op->mem.base_reg;
        mod = 0xB;

        if (op->mem.offset_symbol) {
            disp = 0;
            add_operand_relocation(op);
        } else {
            disp = op->mem.offset;
        }
    } else {
        CHECK_LITERAL_OR_SYMBOL(*op, 3);
        regA = r1->reg;
        mod = 0x3;
        disp = 0;
        add_operand_relocation(op);
    }

    emit_instruction(0x3, mod, regA, regB, regC, disp);
}

void assembler_handle_xchg(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x4, 0x0, 0, r1->reg, r2->reg, 0);
}

void assembler_handle_add(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x0, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_sub(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x1, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_mul(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x2, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_div(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x3, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_not(const Operand* r) {
    CHECK_REG(*r, 1);
    emit_instruction(0x6, 0x0, r->reg, r->reg, 0, 0);
}

void assembler_handle_and(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x6, 0x1, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_or(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x6, 0x2, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_xor(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x6, 0x3, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_shl(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x7, 0x0, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_shr(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x7, 0x1, r1->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_ld(const Operand* src, const Operand* dst) {
    CHECK_REG(*dst, 2);

    uint8_t mod;
    uint8_t regA = dst->reg;
    uint8_t regB = 0;
    uint8_t regC = 0;
    int16_t disp = 0;

    switch (src->type) {
        case OPERAND_MEM:
            regB = src->mem.base_reg;
        	regC = src->mem.index_reg;
            disp = src->mem.offset_symbol ? 0 : src->mem.offset;
            add_operand_relocation(src);
            mod = 0x2;
			break;

		case OPERAND_NUMBER:
            disp = src->literal;
			mod = 0x1;
			break;

        case OPERAND_SYMBOL:
        case OPERAND_LITERAL:
            add_operand_relocation(src);
            mod = 0x1;
            break;

        default:
            fprintf(stderr, "Invalid operand type for ld: %d\n", src->type);
            exit(1);
    }

    emit_instruction(0x9, mod, regA, regB, regC, disp);
}

void assembler_handle_st(const Operand* src, const Operand* dst) {
    CHECK_REG(*src, 1);

    uint8_t mod;
    uint8_t regA = 0;
    uint8_t regB = 0;
    uint8_t regC = src->reg;
    int32_t disp = 0;

    switch (dst->type) {
        case OPERAND_MEM:
            regA = dst->mem.base_reg;
            regB = dst->mem.index_reg;
            disp = dst->mem.offset_symbol ? 0 : dst->mem.offset;
            add_operand_relocation(dst);
            mod = 0x2;
            break;

		case OPERAND_NUMBER:
            disp = dst->literal;
			mod = 0x2;
			break;

        case OPERAND_SYMBOL:
        case OPERAND_LITERAL:
            disp = 0;
            add_operand_relocation(dst);
            mod = 0x2;
            break;

        default:
            fprintf(stderr, "Invalid operand type for st: %d\n", dst->type);
            exit(1);
    }

    emit_instruction(0x8, mod, regA, regB, regC, disp);
}

void assembler_handle_csrrd(const Operand* csr, const Operand* r) {
    CHECK_CSR(*csr, 1);
    CHECK_REG(*r, 2);
    emit_instruction(0x9, 0x0, r->reg, csr->csr, 0, 0);
}

void assembler_handle_csrwr(const Operand* r, const Operand* csr) {
    CHECK_REG(*r, 1);
    CHECK_CSR(*csr, 2);
    emit_instruction(0x9, 0x4, csr->csr, 0, r->reg, 0);
}

void write_output_file(const char* filename) {
	FILE *f = fopen(filename, "wb");
	if (!f) {
		fprintf(stderr, "Error opening output file '%s': %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fwrite(&section_count, sizeof(section_count), 1, f);

	for (int i = 0; i < section_count; i++) {
		Section *sec = &sections[i];
		fwrite(sec->name, sizeof(sec->name), 1, f);
		fwrite(&sec->size, sizeof(sec->size), 1, f);
		fwrite(sec->data, 1, sec->size, f);
	}

	fwrite(&symbol_count, sizeof(symbol_count), 1, f);
	for (size_t i = 0; i < symbol_count; i++) {
		Symbol *sym = &symbols[i];
		uint32_t name_len = (uint32_t)strlen(sym->name);
		fwrite(&name_len, sizeof(name_len), 1, f);
		fwrite(sym->name, 1, name_len, f);

		fwrite(&sym->offset, sizeof(sym->offset), 1, f);

		if (sym->section) {
			uint32_t section_len = (uint32_t)strlen(sym->section);
			fwrite(&section_len, sizeof(section_len), 1, f);
			fwrite(sym->section, 1, section_len, f);
		} else {
			uint32_t section_len = 0;
			fwrite(&section_len, sizeof(section_len), 1, f);
		}

		fwrite(&sym->defined, sizeof(sym->defined), 1, f);
		fwrite(&sym->global, sizeof(sym->global), 1, f);
		fwrite(&sym->external, sizeof(sym->external), 1, f);
	}

	fwrite(&reloc_count, sizeof(reloc_count), 1, f);
	for (size_t i = 0; i < reloc_count; i++) {
		Relocation *rel = &relocations[i];

		uint32_t sec_len = (uint32_t)strlen(rel->section->name);
		fwrite(&sec_len, sizeof(sec_len), 1, f);
		fwrite(rel->section->name, 1, sec_len, f);

		fwrite(&rel->offset, sizeof(rel->offset), 1, f);

		uint32_t sym_len = (uint32_t)strlen(rel->symbol);
		fwrite(&sym_len, sizeof(sym_len), 1, f);
		fwrite(rel->symbol, 1, sym_len, f);

		fwrite(&rel->type, sizeof(rel->type), 1, f);
	}

	fclose(f);
}

void write_text_output_file(const char* filename) {
	FILE *f = fopen(filename, "w");
	if (!f) {
		fprintf(stderr, "Error opening text output file '%s': %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fprintf(f, "=== Sections (%d) ===\n", section_count);
	for (int i = 0; i < section_count; i++) {
		Section *sec = &sections[i];
		fprintf(f, ".section %s (size: %zu bytes):\n", sec->name, sec->size);
		for (uint32_t j = 0; j < sec->size; j++) {
			fprintf(f, "%02X ", sec->data[j]);
			if ((j + 1) % 16 == 0) fprintf(f, "\n");
		}
		if (sec->size % 16 != 0) fprintf(f, "\n");
		fprintf(f, "\n");
	}

	fprintf(f, "=== Symbols (%zu) ===\n", symbol_count);
	for (size_t i = 0; i < symbol_count; i++) {
		Symbol *sym = &symbols[i];
		fprintf(f, "Symbol: %s\n", sym->name);
		fprintf(f, "  Offset: 0x%zX\n", sym->offset);
		fprintf(f, "  Section: %s\n", sym->section ? sym->section : "(none)");
		fprintf(f, "  Defined: %s\n", sym->defined ? "yes" : "no");
		fprintf(f, "  Global: %s\n", sym->global ? "yes" : "no");
		fprintf(f, "  External: %s\n", sym->external ? "yes" : "no");
		fprintf(f, "\n");
	}

	fprintf(f, "=== Relocations (%zu) ===\n", reloc_count);
	for (size_t i = 0; i < reloc_count; i++) {
		Relocation *rel = &relocations[i];
		fprintf(f, "Relocation #%zu\n", i);
		fprintf(f, "  Section: %s\n", rel->section->name);
		fprintf(f, "  Offset: 0x%zX\n", rel->offset);
		fprintf(f, "  Symbol: %s\n", rel->symbol);
		fprintf(f, "  Type: %d\n", rel->type);
		fprintf(f, "\n");
	}

	fclose(f);
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-o output_file] <input_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	const char *input_filename = NULL;
	const char *output_filename = NULL;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-o") == 0) {
			if (i + 1 < argc) {
				output_filename = argv[i + 1];
				i++;
			} else {
				fprintf(stderr, "Error: Missing output filename after -o\n");
				return EXIT_FAILURE;
			}
		} else {
			input_filename = argv[i];
		}
	}

	if (!input_filename) {
		fprintf(stderr, "Error: No input file specified\n");
		return EXIT_FAILURE;
	}

	yyin = fopen(input_filename, "r");
	if (!yyin) {
		perror("Error opening input file");
		return EXIT_FAILURE;
	}

	int parse_result = yyparse();
	fclose(yyin);

	if (parse_result != 0) {
		fprintf(stderr, "Parsing failed with code %d\n", parse_result);
		return EXIT_FAILURE;
	}

	if (output_filename) {
		write_output_file(output_filename);

		char hex_filename[64];
		snprintf(hex_filename, sizeof(hex_filename), "%s.hex", output_filename);
		write_text_output_file(hex_filename);
	} else {
		printf("No output file specified, output omitted\n");
	}

	return EXIT_SUCCESS;
}
