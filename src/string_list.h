#ifndef STRING_LIST_H
#define STRING_LIST_H

#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>

extern char* g_current_yytext;

typedef struct Operand {
    enum {
		OPERAND_REG,
		OPERAND_CSR,
		OPERAND_LITERAL,
		OPERAND_SYMBOL,
		OPERAND_MEM,
		OPERAND_ADDR_SYMBOL,
		OPERAND_ADDR_LITERAL
	} type;
    union {
        int reg;
        int csr;
        int literal;
        char* symbol;
        struct {
            int base_reg;
			int index_reg;
            int offset;
            char* offset_symbol;
        } mem;
    };
} Operand;

typedef struct Expression {
	enum {
		NONE,
		ADDITION,
		SUBSTRACTION
	} operation;
	Operand op1;
	Operand op2;
} Expression;

typedef struct {
    char** data;
    int size;
    int capacity;
} StringList;

static inline StringList* create_string_list() {
    StringList* list = malloc(sizeof(StringList));
    list->size = 0;
    list->capacity = 8;
    list->data = malloc(sizeof(char*) * list->capacity);
    return list;
}

static inline void string_list_push_back(StringList* list, const char* str) {
    if (list->size >= list->capacity) {
        list->capacity *= 2;
        list->data = realloc(list->data, sizeof(char*) * list->capacity);
    }
    list->data[list->size++] = strdup(str);
}

static inline void free_string_list(StringList* list) {
    for (int i = 0; i < list->size; ++i)
        free(list->data[i]);
    free(list->data);
    free(list);
}

#endif
