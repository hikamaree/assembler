#ifndef ELF_FORMAT_H
#define ELF_FORMAT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_REGISTERS 16
#define MAX_SYMBOLS 1024
#define MAX_RELOCATIONS 1024

typedef struct {
    char *name;
    int offset;
    char *section;
    bool defined;
    bool global;
    bool external;
	bool relocatable;
	bool dpool;
} Symbol;

typedef struct {
    char name[64];
    unsigned char *data;
    size_t capacity;
    size_t size;
	size_t base;

    unsigned char *dpool_data;
    size_t dpool_capacity;
    size_t dpool_size;
} Section;

typedef enum {
    RELOC_ABS,
    RELOC_PC_REL
} RelocType;

typedef struct {
    Section *section;
    size_t offset;
	size_t size;
    char *symbol;
    RelocType type;
	bool dpool;
} Relocation;

#endif
