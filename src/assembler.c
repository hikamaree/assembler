#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "assembler.h"
#include "elf_format.h"

extern int yyparse(void);
extern FILE *yyin;

char* g_current_yytext = NULL;

#define CHECK_REG(op, idx) \
    if ((op).type != OPERAND_REG) { \
        fprintf(stderr, "Operand %d must be a register\n", idx); \
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
    char* symbol;
	Expression* expression;
} EquSymbol;

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

static EquSymbol equ_symbols[MAX_SYMBOLS];
static size_t equ_symbol_count = 0;

static char *pending_mem_symbols[MAX_SYMBOLS];
static size_t pending_mem_count = 0;

static Section sections[64];
static size_t section_count = 0;

Section *get_section(const char *name) {
    for (size_t i = 0; i < section_count; i++) {
        if (strcmp(sections[i].name, name) == 0)
            return &sections[i];
    }
    Section *sec = &sections[section_count++];
    strncpy(sec->name, name, sizeof(sec->name)-1);
    sec->capacity = 0xFFF;
    sec->data = malloc(sec->capacity);
    sec->size = 0;
    sec->base = 0;
	sec->dpool_capacity=0xFFF;
	sec->dpool_data = malloc(sec->dpool_capacity);
	sec->dpool_size = 0;
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
	sym->relocatable = false;
	sym->dpool = false;
    return sym;
}

bool pending_has_mem_symbol(const char *name) {
    for (size_t i = 0; i < pending_mem_count; i++) {
        if (strcmp(pending_mem_symbols[i], name) == 0)
            return true;
    }
    return false;
}

void pending_add_mem_symbol(const char *name) {
    if (pending_has_mem_symbol(name)) return;
    if (pending_mem_count >= MAX_SYMBOLS) {
        fprintf(stderr, "Too many pending MEM symbols (global)\n");
        exit(1);
    }
    pending_mem_symbols[pending_mem_count++] = strdup(name);
}

void pending_remove_mem_symbol(const char *name) {
    for (size_t i = 0; i < pending_mem_count; i++) {
        if (strcmp(pending_mem_symbols[i], name) == 0) {
            free(pending_mem_symbols[i]);
            memmove(&pending_mem_symbols[i], &pending_mem_symbols[i + 1],
                    (pending_mem_count - i - 1) * sizeof(char *));
            pending_mem_count--;
            return;
        }
    }
}

int32_t calc_expression(Expression* e) {
    int32_t result = 0;
	Expression* cur = e;

    while(cur != NULL) {
        int32_t value = 0;

        if (cur->operand.type == OPERAND_LITERAL) {
            value = cur->operand.literal;
        } else if (cur->operand.type == OPERAND_SYMBOL) {
            Symbol* sym = find_symbol(cur->operand.symbol);
            free(cur->operand.symbol);
            if (!sym) {
                fprintf(stderr, "Unknown symbol: %s\n", cur->operand.symbol);
                exit(1);
            }
            if (!sym->defined) {
                fprintf(stderr, "Extern symbols are not supported in expressions\n");
                exit(1);
            }
            value = sym->offset;
        } else {
            fprintf(stderr, "Invalid expression operand type %d\n", cur->operand.type);
            exit(1);
        }

        if (cur->op == OP_ADD || cur->op == NONE) {
            result += value;
        } else if (cur->op == OP_SUB) {
            result -= value;
        } else {
            fprintf(stderr, "Unknown operator %d\n", cur->op);
            exit(1);
        }
		Expression* next = cur->next;
		free(cur);
		cur = next;
    }

    return result;
}

void calc_expressions() {
    bool progress;
    size_t remaining = equ_symbol_count;
    bool* evaluated = calloc(equ_symbol_count, sizeof(bool));

    do {
        progress = false;

        for (size_t i = 0; i < equ_symbol_count; i++) {
            if (evaluated[i]) continue;

            EquSymbol esym = equ_symbols[i];
            Symbol* sym = find_symbol(esym.symbol);
            if (!sym) sym = add_symbol(esym.symbol);

            int32_t value = 0;
            bool can_eval = true;

            for (Expression* cur = esym.expression; cur != NULL; cur = cur->next) {
                if (cur->operand.type == OPERAND_SYMBOL) {
                    Symbol* s = find_symbol(cur->operand.symbol);
                    if (!s || !s->defined) {
                        can_eval = false;
                        break;
                    }
                }
            }

            if (can_eval) {
                value = calc_expression(esym.expression);
                sym->offset = value;
                sym->defined = true;
                sym->relocatable = false;

                if (pending_has_mem_symbol(esym.symbol)) {
                    if (sym->offset < -2048 || sym->offset > 2047) {
                        fprintf(stderr, "Symbol %s offset 0x%X too large to embed in prior MEM operand usage.\n", esym.symbol, sym->offset);
                        exit(EXIT_FAILURE);
                    }
                    pending_remove_mem_symbol(esym.symbol);
                }

                evaluated[i] = true;
                progress = true;
                remaining--;
            }
        }

        if (!progress && remaining > 0) {
            fprintf(stderr, "Cannot evaluate some symbols due to undefined dependencies or cycles.\n");
            exit(EXIT_FAILURE);
        }
    } while (remaining > 0);

    free(evaluated);
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
    relocations[reloc_count].dpool = false;

	if(type == RELOC_PC_REL) {
		find_symbol(symbol)->relocatable = true;
	}

    reloc_count++;
}

void add_dpool_relocation(Section *sec, size_t offset, const char *symbol, RelocType type) {
    if (reloc_count >= MAX_RELOCATIONS) {
        fprintf(stderr, "Previše relokacija!\n");
        exit(1);
    }
    relocations[reloc_count].section = sec;
    relocations[reloc_count].offset = offset;
    relocations[reloc_count].size = 4;
    relocations[reloc_count].symbol = strdup(symbol);
    relocations[reloc_count].type = type;
    relocations[reloc_count].dpool = true;
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

uint32_t append_disp_value(const Operand* op) {
    char key[64];
    if (op->type == OPERAND_SYMBOL || op->type == OPERAND_ADDR_SYMBOL) {
        snprintf(key, sizeof(key), "SYM_%s", op->symbol);
    } else if (op->type == OPERAND_LITERAL || op->type == OPERAND_ADDR_LITERAL) {
        snprintf(key, sizeof(key), "LIT_%08X", (uint32_t)op->literal);
    } else {
        fprintf(stderr, "Unsupported operand type in append_disp_value\n");
        exit(1);
    }

    Section* sec = get_section(state.current_section);

    if (!sec->dpool_data) {
        sec->dpool_data = NULL;
        sec->dpool_capacity = 0;
        sec->dpool_size = 0;
    }

    Symbol* sym = find_symbol(key);
    if (sym && sym->defined) {
        return sym->offset;
    }

    uint32_t offset = (uint32_t)sec->dpool_size;

    uint32_t val = 0;
    if (op->type == OPERAND_SYMBOL || op->type == OPERAND_ADDR_SYMBOL) {
        val = 0;
    } else {
        val = (uint32_t)op->literal;
    }

    uint8_t be[4] = {
        (val >> 24) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 8) & 0xFF,
        val & 0xFF
    };

    memcpy(sec->dpool_data + sec->dpool_size, be, 4);
    sec->dpool_size += 4;

    if (!sym) {
        sym = add_symbol(key);
    }
    sym->defined = true;
    free(sym->section);
    sym->section = strdup(sec->name);
    sym->offset = offset;
    sym->relocatable = false;
	sym->dpool = true;

    if (op->type == OPERAND_SYMBOL || op->type == OPERAND_ADDR_SYMBOL) {
        add_dpool_relocation(sec, offset, op->symbol, RELOC_ABS);
    }

    return offset;
}

void assembler_handle_label(const char* label) {
	Symbol* sym = add_symbol(label);
	if (sym->defined) {
		fprintf(stderr, "Error: symbol '%s' is already defined!\n", label);
		exit(EXIT_FAILURE);
	}

	sym->defined = true;
	sym->relocatable = true;
	sym->section = strdup(state.current_section);

	Section* sec = get_section(state.current_section);
	sym->offset = sec->size;

    if (pending_has_mem_symbol(label)) {
		if (sym->offset < -2048 || sym->offset > 2047) {
            fprintf(stderr, "Symbol %s offset 0x%X too large to embed in prior MEM operand usage.\n", label, sym->offset);
            exit(EXIT_FAILURE);
        }
        pending_remove_mem_symbol(label);
    }
}

void assembler_handle_section(const char* section_name) {
	strncpy(state.current_section, section_name, sizeof(state.current_section) - 1);
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

void assembler_handle_word(const StringList* words) {
	Section *sec = get_section(state.current_section);
	for (int i = 0; i < words->size; i++) {
		const char *w = words->data[i];
		uint32_t val = 0;
		if (is_literal(w)) {
			val =(uint32_t)strtoul(w, NULL, 0); 
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

void assembler_handle_equ(char* symbol, Expression* expression) {
	equ_symbols[equ_symbol_count].expression = expression;
	equ_symbols[equ_symbol_count].symbol = symbol;
	equ_symbol_count ++;
};

void assembler_handle_end(void) {
	state.end_encountered = true;
}

void assembler_handle_ascii(const char* str) {
    Section *sec = get_section(state.current_section);
    section_write_bytes(sec, (const unsigned char*)str, strlen(str));
    uint8_t zero = 0;
    while (sec->size % 4 != 0) {
        section_write_bytes(sec, &zero, 1);
    }
}

static void emit(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
    uint8_t encoded[4] = { b0, b1, b2, b3 };
    Section* sec = get_section(state.current_section);
    section_write_bytes(sec, encoded, 4);
}

void emit_instruction(uint8_t oc, uint8_t mod, uint8_t regA, uint8_t regB, uint8_t regC, int16_t disp) {
	if (disp < -2048 || disp >= 2048) {
        fprintf(stderr, "Disp out of range: %X (%d)\n", disp, disp);
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
    emit_instruction(0x8, 0x1, 14, 0, r->reg, 0xFFFC);
}

void assembler_handle_pop(const Operand* r) {
    CHECK_REG(*r, 1);
    emit_instruction(0x9, 0x3, r->reg, 14, 0, 4);
}

void assembler_handle_call(const Operand* op) {
    uint8_t mod;
    uint8_t regA = 0, regB = 0, regC = 0;
    int16_t disp = 0;

    Section *sec = get_section(state.current_section);

    switch (op->type) {
			case OPERAND_MEM: {
			    mod = 0x1;
			    regA = op->mem.base_reg;
			    regB = op->mem.index_reg;
				if (op->mem.offset_symbol) {
				    Symbol* sym = find_symbol(op->mem.offset_symbol);
				    if (sym && sym->defined) {
				        if (sym->offset < -2048 || sym->offset > 2047) {
				            fprintf(stderr, "Symbol %s offset 0x%X too large to embed in MEM operand.\n", op->mem.offset_symbol, sym->offset);
				            exit(1);
				        }
			    		if (sym->relocatable) {
			    		    fprintf(stderr, "Symbol %s used in MEM operand can not be relocatable.\n", op->mem.offset_symbol);
			    		    exit(1);
			    		}
				    } else {
				        pending_add_mem_symbol(op->mem.offset_symbol);
				    }
				    add_operand_relocation(op);
				} else {
				    disp = op->mem.offset;
				}
			    break;
			}
        case OPERAND_ADDR_SYMBOL:
            append_disp_value(op);

            mod = 0x1;
            regA = 15;
            regB = 0;

            char symname[64];
            snprintf(symname, sizeof(symname), "SYM_%s", op->symbol);
            add_relocation(sec, sec->size, symname, RELOC_PC_REL);
			break;

        case OPERAND_ADDR_LITERAL: {
		    if (op->literal >= -2048 && op->literal < 2048) {
                mod = 0x0;
                regA = 0;
                regB = 0;
                disp = (int16_t)op->literal;
            } else {
                append_disp_value(op);

                mod = 0x1;
                regA = 15;
                regB = 0;

                char symname[64];
                snprintf(symname, sizeof(symname), "LIT_%08X", (uint32_t)op->literal);
                add_relocation(sec, sec->size, symname, RELOC_PC_REL);
            }
			break;
        }

        default:
            fprintf(stderr, "Invalid operand type for call\n");
            exit(1);
    }

	emit_instruction(0x2, mod, regA, regB, regC, disp);
}

static void assembler_handle_cond_jump(const Operand* r1, const Operand* r2, const Operand* op, uint8_t mod_d, uint8_t mod_i) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    uint8_t mod = 0;
    uint8_t regA = 0, regB = r1->reg, regC = r2->reg;
    int16_t disp = 0;

    Section *sec = get_section(state.current_section);

    if (op->type == OPERAND_MEM) {
        regA = op->mem.base_reg;
        mod = mod_i;
		if (op->mem.offset_symbol) {
		    Symbol* sym = find_symbol(op->mem.offset_symbol);
		    if (sym && sym->defined) {
				if (sym->offset < -2048 || sym->offset > 2047) {
		            fprintf(stderr, "Symbol %s offset 0x%X too large to embed in MEM operand.\n", op->mem.offset_symbol, sym->offset);
		            exit(1);
		        }
			    if (sym->relocatable) {
			        fprintf(stderr, "Symbol %s used in MEM operand can not be relocatable.\n", op->mem.offset_symbol);
			        exit(1);
			    }
		    } else {
		        pending_add_mem_symbol(op->mem.offset_symbol);
		    }
		    add_operand_relocation(op);
		} else {
		    disp = op->mem.offset;
		}
    } else if (op->type == OPERAND_ADDR_SYMBOL) {
        append_disp_value(op);

        mod = mod_i;
        regA = 15;
        char symname[64];
        snprintf(symname, sizeof(symname), "SYM_%s", op->symbol);
        add_relocation(sec, sec->size, symname, RELOC_PC_REL);
    } else if (op->type == OPERAND_ADDR_LITERAL) {
		if (op->literal >= -2048 && op->literal < 2048) {
            mod = mod_d;
            regA = 0;
            disp = (int16_t)op->literal;
        } else {
            append_disp_value(op);
            mod = mod_i;
            regA = 15;

            char symname[32];
            snprintf(symname, sizeof(symname), "LIT_%08X", (uint32_t)op->literal);
            add_relocation(sec, sec->size, symname, RELOC_PC_REL);
        }
    } else {
        fprintf(stderr, "Invalid operand type for conditional jump\n");
        exit(1);
    }

    emit_instruction(0x3, mod, regA, regB, regC, disp);
}

void assembler_handle_jmp(const Operand* op) {
    Operand r0 = { .type = OPERAND_REG, .reg = 0 };
    assembler_handle_cond_jump(&r0, &r0, op, 0x0, 0x8);
}

void assembler_handle_beq(const Operand* r1, const Operand* r2, const Operand* op) {
    assembler_handle_cond_jump(r1, r2, op, 0x1, 0x9);
}

void assembler_handle_bne(const Operand* r1, const Operand* r2, const Operand* op) {
    assembler_handle_cond_jump(r1, r2, op, 0x2, 0xA);
}

void assembler_handle_bgt(const Operand* r1, const Operand* r2, const Operand* op) {
    assembler_handle_cond_jump(r1, r2, op, 0x3, 0xB);
}

void assembler_handle_xchg(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x4, 0x0, 0, r1->reg, r2->reg, 0);
}

void assembler_handle_add(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x0, r2->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_sub(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x1, r2->reg, r2->reg, r1->reg, 0);
}

void assembler_handle_mul(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x2, r2->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_div(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);
    emit_instruction(0x5, 0x3, r2->reg, r2->reg, r1->reg, 0);
}

void assembler_handle_not(const Operand* r) {
    CHECK_REG(*r, 1);
    emit_instruction(0x6, 0x0, r->reg, r->reg, 0, 0);
}

void assembler_handle_and(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x6, 0x1, r2->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_or(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x6, 0x2, r2->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_xor(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x6, 0x3, r2->reg, r1->reg, r2->reg, 0);
}

void assembler_handle_shl(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x7, 0x0, r2->reg, r2->reg, r1->reg, 0);
}

void assembler_handle_shr(const Operand* r1, const Operand* r2) {
    CHECK_REG(*r1, 1);
    CHECK_REG(*r2, 2);

    emit_instruction(0x7, 0x1, r2->reg, r2->reg, r1->reg, 0);
}


void assembler_handle_ld(const Operand* src, const Operand* dst) {
    CHECK_REG(*dst, 2);

    uint8_t mod;
    uint8_t regA = dst->reg;
    uint8_t regB = 15;
    uint8_t regC = 0;
    int16_t disp = 0;

    Section *sec = get_section(state.current_section);

    switch (src->type) {
		case OPERAND_REG:
			mod = 0x1;
			regB = src->reg;
			break;
        case OPERAND_MEM:
            mod = 0x2;
            regB = src->mem.base_reg;
            regC = src->mem.index_reg;
			if (src->mem.offset_symbol) {
			    Symbol* sym = find_symbol(src->mem.offset_symbol);
			    if (sym && sym->defined) {
					if (sym->offset < -2048 || sym->offset > 2047) {
			            fprintf(stderr, "Symbol %s offset 0x%X too large to embed in MEM operand.\n", src->mem.offset_symbol, sym->offset);
			            exit(1);
			        }
			        if (sym->relocatable) {
			            fprintf(stderr, "Symbol %s used in MEM operand can not be relocatable.\n", dst->mem.offset_symbol);
			            exit(1);
			        }
			    } else {
			        pending_add_mem_symbol(src->mem.offset_symbol);
			    }
			    add_operand_relocation(src);
			} else {
			    disp = src->mem.offset;
			}
            break;

		case OPERAND_SYMBOL:
		    append_disp_value(src);

		    mod = 0x2;
		    regB = 15;
		    regC = 0;

		    char symname[64];
		    snprintf(symname, sizeof(symname), "SYM_%s", src->symbol);
		    add_relocation(sec, sec->size, symname, RELOC_PC_REL);
			break;

		case OPERAND_LITERAL:
		    if (src->literal >= -2048 && src->literal < 2048) {
		        mod = 0x1;
		        regB = 0;
		        regC = 0;
		        disp = (uint16_t)src->literal;
		    } else {
		        append_disp_value(src);

		        mod = 0x2;
		        regB = 15;
		        regC = 0;

		        char symname[32];
		        snprintf(symname, sizeof(symname), "LIT_%08X", (uint32_t)src->literal);
		        add_relocation(sec, sec->size, symname, RELOC_PC_REL);
			}
		    break;

        case OPERAND_ADDR_SYMBOL: {
		    	append_disp_value(src);

		    	mod = 0x2;
		    	regB = 15;
		    	regC = 0;

		    	char symname[64];
		    	snprintf(symname, sizeof(symname), "SYM_%s", src->symbol);
		    	add_relocation(sec, sec->size, symname, RELOC_PC_REL);
            	emit_instruction(0x9, mod, regA, regB, regC, disp);

                mod = 0x2;
                regB = dst->reg;
                regC = 0;
                disp = 0;
            }
			break;

        case OPERAND_ADDR_LITERAL:
		    if (src->literal >= -2048 && src->literal < 2048) {
                mod = 0x1;
                regB = 0;
                regC = 0;
                disp = (uint16_t)src->literal;
                emit_instruction(0x9, mod, regA, regB, regC, disp);

                mod = 0x2;
                regB = dst->reg;
                regC = 0;
                disp = 0;
            } else {
                append_disp_value(src);
                mod = 0x2;
                regB = 15;
                regC = 0;
                disp = 0;
                char symname[32];
                snprintf(symname, sizeof(symname), "LIT_%08X", (uint32_t)src->literal);
                add_relocation(sec, sec->size, symname, RELOC_PC_REL);
                emit_instruction(0x9, mod, regA, regB, regC, disp);

                mod = 0x2;
                regB = dst->reg;
                regC = 0;
                disp = 0;
            }
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
    int16_t disp = 0;

    Section *sec = get_section(state.current_section);

    switch (dst->type) {
        case OPERAND_MEM:
            mod = 0x0;
            regA = dst->mem.base_reg;
            regB = dst->mem.index_reg;
			if (dst->mem.offset_symbol) {
			    Symbol* sym = find_symbol(dst->mem.offset_symbol);
			    if (sym && sym->defined) {
					if (sym->offset < -2048 || sym->offset > 2047) {
			            fprintf(stderr, "Symbol %s offset 0x%X too large to embed in MEM operand.\n", dst->mem.offset_symbol, sym->offset);
			            exit(1);
			        }
			        if (sym->relocatable) {
			            fprintf(stderr, "Symbol %s used in MEM operand can not be relocatable.\n", dst->mem.offset_symbol);
			            exit(1);
			        }
			    } else {
			        pending_add_mem_symbol(dst->mem.offset_symbol);
			    }
			    add_operand_relocation(dst);
			} else {
			    disp = dst->mem.offset;
			}
            break;

        case OPERAND_ADDR_SYMBOL: 
            append_disp_value(dst);

            mod = 0x2;
            regA = 15;
            regB = 0;

            char symname[64];
            snprintf(symname, sizeof(symname), "SYM_%s", dst->symbol);
            add_relocation(sec, sec->size, symname, RELOC_PC_REL);
			break;

        case OPERAND_ADDR_LITERAL:
		    if (dst->literal >= -2048 && dst->literal < 2048) {
                mod = 0x0;
                regA = 0;
                regB = 0;
                disp = (int16_t)dst->literal;
            } else {
                append_disp_value(dst);

                mod = 0x2;
                regA = 15;
                regB = 0;

                char symname[32];
                snprintf(symname, sizeof(symname), "LIT_%08X", (uint32_t)dst->literal);
                add_relocation(sec, sec->size, symname, RELOC_PC_REL);
        	}
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
    emit_instruction(0x9, 0x4, csr->csr, r->reg, 0, 0);
}

void flatten_all_dpools(void) {
    for (size_t i = 0; i < section_count; i++) {
        Section *sec = &sections[i];
        if (sec->dpool_size == 0) continue;

        size_t old_size = sec->size;
        size_t dpool_size = sec->dpool_size;
        size_t new_size = old_size + dpool_size;

        if (new_size > sec->capacity) {
            unsigned char *new_data = realloc(sec->data, new_size);
            if (!new_data) {
                fprintf(stderr, "OOM while flattening dpool for section %s\n", sec->name);
                exit(1);
            }
            sec->data = new_data;
            sec->capacity = new_size;
        }

        memcpy(sec->data + old_size, sec->dpool_data, dpool_size);
        sec->size = new_size;

        for (size_t si = 0; si < symbol_count; si++) {
            Symbol *s = &symbols[si];
            if (s->dpool && s->section && strcmp(s->section, sec->name) == 0) {
                s->offset += old_size;
                s->dpool = false;
            }
        }

        extern Relocation relocations[];
        extern size_t reloc_count;
        for (size_t ri = 0; ri < reloc_count; ri++) {
            Relocation *r = &relocations[ri];
            if (r->dpool && r->section == sec) {
                r->offset += old_size;
                r->dpool = false;
            }
        }

        free(sec->dpool_data);
        sec->dpool_data = NULL;
        sec->dpool_size = 0;
        sec->dpool_capacity = 0;
    }
}


static void write_exact(FILE *f, const void *buf, size_t sz) {
    if (fwrite(buf, 1, sz, f) != sz) {
        fprintf(stderr, "I/O write error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void write_output_file(const char* filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Error opening output file '%s': %s\n", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    uint32_t sc = (uint32_t)section_count;
    write_exact(f, &sc, sizeof(sc));
    for (uint32_t i = 0; i < sc; i++) {
        Section *sec = &sections[i];
        write_exact(f, sec->name, 64);
        uint64_t sz = (uint64_t)sec->size;
        write_exact(f, &sz, sizeof(sz));
        write_exact(f, sec->data, sec->size);
    }

    uint32_t symc = (uint32_t)symbol_count;
    write_exact(f, &symc, sizeof(symc));
    for (uint32_t i = 0; i < symc; i++) {
        Symbol *sym = &symbols[i];
        uint32_t name_len = (uint32_t)strlen(sym->name);
        write_exact(f, &name_len, sizeof(name_len));
        write_exact(f, sym->name, name_len);

        uint64_t offset = (uint64_t)sym->offset;
        write_exact(f, &offset, sizeof(offset));

        if (sym->section) {
            uint32_t section_len = (uint32_t)strlen(sym->section);
            write_exact(f, &section_len, sizeof(section_len));
            write_exact(f, sym->section, section_len);
        } else {
            uint32_t section_len = 0;
            write_exact(f, &section_len, sizeof(section_len));
        }

        uint8_t defined = sym->defined ? 1 : 0;
        uint8_t global = sym->global ? 1 : 0;
        uint8_t external = sym->external ? 1 : 0;
        uint8_t relocatable = sym->relocatable ? 1 : 0;
        write_exact(f, &defined, sizeof(defined));
        write_exact(f, &global, sizeof(global));
        write_exact(f, &external, sizeof(external));
        write_exact(f, &relocatable, sizeof(relocatable));
    }

    uint32_t rc = (uint32_t)reloc_count;
    write_exact(f, &rc, sizeof(rc));
    for (uint32_t i = 0; i < rc; i++) {
        Relocation *rel = &relocations[i];

        uint32_t sec_len = (uint32_t)strlen(rel->section->name);
        write_exact(f, &sec_len, sizeof(sec_len));
        write_exact(f, rel->section->name, sec_len);

        uint64_t offset = (uint64_t)rel->offset;
        write_exact(f, &offset, sizeof(offset));

        uint32_t sym_len = (uint32_t)strlen(rel->symbol);
        write_exact(f, &sym_len, sizeof(sym_len));
        write_exact(f, rel->symbol, sym_len);

        uint32_t type = (uint32_t)rel->type;
        write_exact(f, &type, sizeof(type));
    }

    fclose(f);
}

void write_text_output_file(const char* filename) {
	FILE *f = fopen(filename, "w");
	if (!f) {
		fprintf(stderr, "Error opening text output file '%s': %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fprintf(f, "#sections\n");
	for (size_t i = 0; i < section_count; i++) {
		Section *sec = &sections[i];
		fprintf(f, ".%s\n", sec->name);
		for (uint32_t j = 0; j < sec->size; j++) {
			fprintf(f, "%02X ", sec->data[j]);
			if ((j + 1) % 16 == 0) fprintf(f, "\n");
		}
		if (sec->size % 16 != 0) fprintf(f, "\n");
	}

	fprintf(f, "\n#symbols\n");
	fprintf(f, "%-4s %-10s %-6s %-6s %s\n", "NUM", "VALUE", "TYPE", "BIND", "NAME");

	for (size_t i = 0; i < symbol_count; i++) {
		Symbol *sym = &symbols[i];
		fprintf(f, "%-4zu 0x%-8X %-6s %-6s %s\n", i, sym->offset,
				sym->relocatable ? "REL" : "NOREL", sym->global ? "GLOB" : "LOC", sym->name);
	}

	fprintf(f, "\n#relocations\n");
	fprintf(f, "%-4s %-10s %-8s %-20s %s\n", "NUM", "OFFSET", "TYPE", "SYMBOL", "SECTION");

	for (size_t i = 0; i < reloc_count; i++) {
		Relocation *rel = &relocations[i];
		fprintf(f, "%-4zu 0x%-8zX %-8s %-20s %s\n", i, rel->offset,
				rel->type == 0 ? "ABS" : "PC_REL", rel->symbol, rel->section->name);
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

	flatten_all_dpools();

	calc_expressions();

	if (pending_mem_count > 0) {
		for (size_t i = 0; i < pending_mem_count; i++) {
			fprintf(stderr, "Undefined MEM symbol '%s'\n", pending_mem_symbols[i]);
		}
		exit(1);
	}

	if (output_filename) {
		write_output_file(output_filename);

		char hex_filename[64];
		snprintf(hex_filename, sizeof(hex_filename), "%s.hex", output_filename);
		write_text_output_file(hex_filename);
	} else {
		printf("No output file specified, output omitted\n");
	}

	for(size_t i = 0; i < symbol_count; i++) {
		free(symbols[i].name);
		free(symbols[i].section);
	}

	for(size_t i = 0; i < reloc_count; i++) {
		free(relocations[i].symbol);
	}

	for(size_t i = 0; i < section_count; i++) {
		free(sections[i].data);
		free(sections[i].dpool_data);
	}

	return EXIT_SUCCESS;
}
