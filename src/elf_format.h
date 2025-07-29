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
    size_t offset;
    char *section;
    bool defined;
    bool global;
    bool external;
} Symbol;

typedef struct {
    char name[64];
    unsigned char *data;
    size_t capacity;
    size_t size;
} Section;

typedef enum {
    RELOC_ABS,
    RELOC_REL
} RelocType;

typedef struct {
    Section *section;
    size_t offset;
	size_t size;
    char *symbol;
    RelocType type;
} Relocation;

#endif
