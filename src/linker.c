#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "elf_format.h"

#define MAX_INPUT_FILES 32
#define MAX_PLACEMENTS 32
#define MAX_SECTIONS 128

typedef struct {
    char section_name[64];
    uint32_t address;
} Placement;

typedef struct {
    char *output_filename;
    bool hex_output;
    bool relocatable_output;
    Placement placements[MAX_PLACEMENTS];
    int placement_count;
    char *input_files[MAX_INPUT_FILES];
    int input_count;
} LinkerOptions;

static Symbol global_symbols[MAX_SYMBOLS];
static size_t global_symbol_count = 0;

static Section sections[MAX_SECTIONS];
static size_t section_count = 0;

static Relocation relocations[MAX_RELOCATIONS];
static size_t relocation_count = 0;

void print_usage() {
    fprintf(stderr,
        "Usage: linker [options] <input_files>\n"
        "Options:\n"
        "  -o <output_file>\n"
        "  -hex\n"
        "  -relocatable\n"
        "  -place=<section>@<address>\n"
    );
}

Section* find_section(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < section_count; i++) {
        if (strcmp(sections[i].name, name) == 0)
            return &sections[i];
    }
    return NULL;
}

Symbol* find_symbol(const char *name) {
    for (size_t i = 0; i < global_symbol_count; i++) {
        if (strcmp(global_symbols[i].name, name) == 0)
            return &global_symbols[i];
    }
    return NULL;
}

void write_u32_le(unsigned char *data, size_t offset, uint32_t value) {
    data[offset+0] = (value >> 0) & 0xFF;
    data[offset+1] = (value >> 8) & 0xFF;
    data[offset+2] = (value >> 16) & 0xFF;
    data[offset+3] = (value >> 24) & 0xFF;
}

bool parse_args(int argc, char **argv, LinkerOptions *opts) {
    memset(opts, 0, sizeof(*opts));
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-hex") == 0) {
            if (opts->relocatable_output) {
                fprintf(stderr, "Error: Cannot use -hex and -relocatable together.\n");
                return false;
            }
            opts->hex_output = true;
        } else if (strcmp(argv[i], "-relocatable") == 0) {
            if (opts->hex_output) {
                fprintf(stderr, "Error: Cannot use -hex and -relocatable together.\n");
                return false;
            }
            opts->relocatable_output = true;
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing filename after -o\n");
                return false;
            }
            opts->output_filename = argv[++i];
        } else if (strncmp(argv[i], "-place=", 7) == 0) {
            if (opts->placement_count >= MAX_PLACEMENTS) {
                fprintf(stderr, "Error: Too many -place options.\n");
                return false;
            }
            char *arg = argv[i] + 7;
            char *at = strchr(arg, '@');
            if (!at) {
                fprintf(stderr, "Error: Invalid -place syntax.\n");
                return false;
            }
            *at = '\0';
            strncpy(opts->placements[opts->placement_count].section_name, arg, sizeof(opts->placements[0].section_name)-1);
            opts->placements[opts->placement_count].address = (uint32_t)strtoul(at + 1, NULL, 0);
            opts->placement_count++;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return false;
        } else {
            if (opts->input_count >= MAX_INPUT_FILES) {
                fprintf(stderr, "Error: Too many input files.\n");
                return false;
            }
            opts->input_files[opts->input_count++] = argv[i];
        }
    }

    if ((opts->hex_output + opts->relocatable_output) != 1) {
        fprintf(stderr, "Error: Must specify exactly one of -hex or -relocatable.\n");
        return false;
    }

    if (opts->input_count == 0) {
        fprintf(stderr, "Error: No input files specified.\n");
        return false;
    }

    if (!opts->output_filename) {
        fprintf(stderr, "Error: Must specify output file with -o\n");
        return false;
    }

    return true;
}

bool load_object_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return false;
    }

    uint32_t sec_count;
    if (fread(&sec_count, sizeof(uint32_t), 1, f) != 1) {
        fprintf(stderr, "Error: Failed to read section count\n");
        fclose(f);
        return false;
    }

    for (uint32_t i = 0; i < sec_count; i++) {
        if (section_count >= MAX_SYMBOLS) {
            fprintf(stderr, "Error: Too many sections\n");
            fclose(f);
            return false;
        }

        Section *sec = &sections[section_count++];
        memset(sec, 0, sizeof(Section));

        if (fread(sec->name, 1, 64, f) != 64) {
            fprintf(stderr, "Error: Failed to read section name\n");
            fclose(f);
            return false;
        }
        sec->name[63] = '\0';

        if (fread(&sec->size, sizeof(size_t), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read section size\n");
            fclose(f);
            return false;
        }

        sec->capacity = sec->size;
        sec->data = malloc(sec->capacity);
        if (!sec->data) {
            fprintf(stderr, "Error: malloc failed for section data\n");
            fclose(f);
            return false;
        }
        if (fread(sec->data, 1, sec->size, f) != sec->size) {
            fprintf(stderr, "Error: Failed to read section data\n");
            fclose(f);
            return false;
        }
    }

    if (fread(&global_symbol_count, sizeof(size_t), 1, f) != 1) {
        fprintf(stderr, "Error: Failed to read symbol count\n");
        fclose(f);
        return false;
    }

    for (size_t i = 0; i < global_symbol_count; i++) {
        if (i >= MAX_SYMBOLS) {
            fprintf(stderr, "Error: Too many symbols\n");
            fclose(f);
            return false;
        }
        Symbol *sym = &global_symbols[i];
        memset(sym, 0, sizeof(Symbol));

        uint32_t name_len;
        if (fread(&name_len, sizeof(uint32_t), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read symbol name length\n");
            fclose(f);
            return false;
        }
        sym->name = malloc(name_len + 1);
        if (!sym->name) {
            fprintf(stderr, "Error: malloc failed for symbol name\n");
            fclose(f);
            return false;
        }
        if (fread(sym->name, 1, name_len, f) != name_len) {
            fprintf(stderr, "Error: Failed to read symbol name\n");
            fclose(f);
            return false;
        }
        sym->name[name_len] = '\0';

        if (fread(&sym->offset, sizeof(size_t), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read symbol offset\n");
            fclose(f);
            return false;
        }

        uint32_t sec_len;
        if (fread(&sec_len, sizeof(uint32_t), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read symbol section name length\n");
            fclose(f);
            return false;
        }
        if (sec_len > 0) {
            char *sec_name = malloc(sec_len + 1);
            if (!sec_name) {
                fprintf(stderr, "Error: malloc failed for symbol section name\n");
                fclose(f);
                return false;
            }
            if (fread(sec_name, 1, sec_len, f) != sec_len) {
                fprintf(stderr, "Error: Failed to read symbol section name\n");
                free(sec_name);
                fclose(f);
                return false;
            }
            sec_name[sec_len] = '\0';
            sym->section = sec_name;
        } else {
            sym->section = NULL;
        }

        if (fread(&sym->defined, sizeof(bool), 1, f) != 1 ||
            fread(&sym->global, sizeof(bool), 1, f) != 1 ||
            fread(&sym->external, sizeof(bool), 1, f) != 1 ||
			fread(&sym->relocatable, sizeof(bool), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read symbol flags\n");
            fclose(f);
            return false;
        }
    }

    if (fread(&relocation_count, sizeof(size_t), 1, f) != 1) {
        fprintf(stderr, "Error: Failed to read relocation count\n");
        fclose(f);
        return false;
    }

    for (size_t i = 0; i < relocation_count; i++) {
        if (i >= MAX_RELOCATIONS) {
            fprintf(stderr, "Error: Too many relocations\n");
            fclose(f);
            return false;
        }

        Relocation *rel = &relocations[i];
        memset(rel, 0, sizeof(Relocation));

        uint32_t sec_len;
        if (fread(&sec_len, sizeof(uint32_t), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read relocation section name length\n");
            fclose(f);
            return false;
        }
        char *sec_name = malloc(sec_len + 1);
        if (!sec_name) {
            fprintf(stderr, "Error: malloc failed for relocation section name\n");
            fclose(f);
            return false;
        }
        if (fread(sec_name, 1, sec_len, f) != sec_len) {
            fprintf(stderr, "Error: Failed to read relocation section name\n");
            free(sec_name);
            fclose(f);
            return false;
        }
        sec_name[sec_len] = '\0';

        rel->section = find_section(sec_name);
        free(sec_name);

        if (!rel->section) {
            fprintf(stderr, "Error: Relocation references unknown section\n");
            fclose(f);
            return false;
        }

        if (fread(&rel->offset, sizeof(size_t), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read relocation offset\n");
            fclose(f);
            return false;
        }

        uint32_t sym_len;
        if (fread(&sym_len, sizeof(uint32_t), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read relocation symbol name length\n");
            fclose(f);
            return false;
        }
        rel->symbol = malloc(sym_len + 1);
        if (!rel->symbol) {
            fprintf(stderr, "Error: malloc failed for relocation symbol name\n");
            fclose(f);
            return false;
        }
        if (fread(rel->symbol, 1, sym_len, f) != sym_len) {
            fprintf(stderr, "Error: Failed to read relocation symbol name\n");
            fclose(f);
            return false;
        }
        rel->symbol[sym_len] = '\0';

        int type_int;
        if (fread(&type_int, sizeof(int), 1, f) != 1) {
            fprintf(stderr, "Error: Failed to read relocation type\n");
            fclose(f);
            return false;
        }
        rel->type = (RelocType)type_int;
    }

    fclose(f);
    return true;
}

bool load_input_files(const LinkerOptions *opts) {
    for (int i = 0; i < opts->input_count; i++) {
        const char *filename = opts->input_files[i];
        if (!load_object_file(filename)) {
            fprintf(stderr, "Error loading object file: %s\n", filename);
            return false;
        }
    }
    return true;
}

bool link_objects(LinkerOptions *opts) {
    uint32_t next_address = 0;

    for (size_t i = 0; i < section_count; i++) {
        Section *sec = &sections[i];
        bool found = false;

        for (int j = 0; j < opts->placement_count; j++) {
            if (strcmp(sec->name, opts->placements[j].section_name) == 0) {
                sec->base = opts->placements[j].address;
                found = true;

                uint32_t end_address = sec->base + sec->size;
                if (end_address > next_address)
                    next_address = end_address;
                break;
            }
        }

        if (!found) {
            sec->base = next_address;
            next_address += sec->size;
        }
    }

    for (size_t i = 0; i < global_symbol_count; i++) {
        Symbol *sym = &global_symbols[i];

        if (!sym->defined) {
            fprintf(stderr, "Error: Undefined symbol %s\n", sym->name);
            return false;
        }

        Section *sec = find_section(sym->section);
        if (!sec) {
            fprintf(stderr, "Error: Symbol %s references unknown section %s\n", sym->name, sym->section);
            return false;
        }

		if(sym->relocatable) {
        	sym->offset += sec->base;
		}
    }

	for (size_t i = 0; i < relocation_count; i++) {
		Relocation *rel = &relocations[i];

		if (!rel->section || !rel->symbol) {
			fprintf(stderr, "Error: Relocation %zu has invalid section or symbol\n", i);
			return false;
		}

		Symbol *target = find_symbol(rel->symbol);
		if (!target || !target->defined) {
			fprintf(stderr, "Error: Undefined symbol in relocation: %s\n", rel->symbol);
			return false;
		}

		Section *sec = rel->section;
		size_t offset = rel->offset;

		printf("=== Section %s content (size = %zu) ===\n", sec->name, sec->size);
		for (size_t b = 0; b < sec->size; b++) {
			if (b % 16 == 0) printf("\n%04zx: ", b);
			printf("%02X ", sec->data[b]);
		}
		printf("\n");

		if (offset + 4 > sec->size) {
			fprintf(stderr, "Error: Relocation offset out of bounds in section %s (offset %zu + 4 > %zu)\n",
					sec->name, offset, sec->size);
			return false;
		}

		if (rel->type == RELOC_ABS) {
			uint32_t abs_addr = target->offset;
			printf("RELOC_ABS: patching absolute address 0x%08X at offset 0x%zX\n", abs_addr, offset);
			sec->data[offset + 0] = sec->data[offset + 0] | ((abs_addr >> 24) & 0xFF);
			sec->data[offset + 1] = sec->data[offset + 1] | ((abs_addr >> 16) & 0xFF);
			sec->data[offset + 2] = sec->data[offset + 2] | ((abs_addr >> 8) & 0xFF);
			sec->data[offset + 3] = sec->data[offset + 3] | ((abs_addr >> 0) & 0xFF);
		} else if (rel->type == RELOC_PC_REL) {
			size_t instr_start = (offset >= 2) ? offset - 2 : 0;
			uint32_t pc = sec->base + instr_start + 4;
			int32_t relative = (int32_t)target->offset - (int32_t)pc;

			if (relative > 0xFFF) {
				fprintf(stderr, "Error: PC-relative relocation out of range for symbol %s (rel = %d)\n",
						rel->symbol, relative);
				return false;
			}

			uint32_t encoded12 = (uint32_t)(relative & 0xFFF);

			uint32_t orig = 0;
			orig |= ((uint32_t)sec->data[instr_start + 0]) << 24;
			orig |= ((uint32_t)sec->data[instr_start + 1]) << 16;
			orig |= ((uint32_t)sec->data[instr_start + 2]) << 8;
			orig |= ((uint32_t)sec->data[instr_start + 3]) << 0;

			uint32_t patched = orig | encoded12;

			sec->data[instr_start + 0] = (patched >> 24) & 0xFF;
			sec->data[instr_start + 1] = (patched >> 16) & 0xFF;
			sec->data[instr_start + 2] = (patched >> 8) & 0xFF;
			sec->data[instr_start + 3] = (patched >> 0) & 0xFF;

			printf("RELOC_PC_REL: target=0x%08zX pc=0x%08X rel=%d encoded=0x%03X\n",
					target->offset, pc, relative, encoded12);
		} else {
			fprintf(stderr, "Error: Unknown relocation type\n");
			return false;
		}
	}

	return true;
}

bool write_output(LinkerOptions *opts) {
    FILE *f = fopen(opts->output_filename, opts->hex_output ? "w" : "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open output file %s\n", opts->output_filename);
        return false;
    }

    if (opts->hex_output) {
        Section* sorted[MAX_SECTIONS];
        size_t sorted_count = section_count;
        for (size_t i = 0; i < section_count; i++) {
            sorted[i] = &sections[i];
        }
        for (size_t i = 1; i < sorted_count; i++) {
            Section* key = sorted[i];
            size_t j = i;
            while (j > 0 && sorted[j - 1]->base > key->base) {
                sorted[j] = sorted[j - 1];
                j--;
            }
            sorted[j] = key;
        }

        for (size_t si = 0; si < sorted_count; si++) {
            Section *sec = sorted[si];
            uint32_t base_addr = (uint32_t)sec->base;
            for (size_t j = 0; j < sec->size; j += 8) {
                fprintf(f, "%08X: ", base_addr + (uint32_t)j);
                size_t line_end = j + 8;
                if (line_end > sec->size)
                    line_end = sec->size;
                for (size_t k = j; k < line_end; k++) {
                    fprintf(f, "%02X", (unsigned char)sec->data[k]);
                    if (k + 1 < line_end)
                        fputc(' ', f);
                }
                fprintf(f, "\n");
            }
        }
    } else if (opts->relocatable_output) {
        for (size_t i = 0; i < section_count; i++) {
            Section *sec = &sections[i];
            fwrite(sec->data, 1, sec->size, f);
        }
    }

    fclose(f);
    return true;
}

int main(int argc, char **argv) {
	LinkerOptions opts;
	if (!parse_args(argc, argv, &opts)) {
		print_usage();
		return 1;
	}

	if (!load_input_files(&opts)) {
		fprintf(stderr, "Failed to load input files\n");
		return 2;
	}

	if (!link_objects(&opts)) {
		fprintf(stderr, "Linking failed\n");
		return 3;
	}

	if (!write_output(&opts)) {
		fprintf(stderr, "Writing output failed\n");
		return 4;
	}

	printf("Linking successful, output: %s\n", opts.output_filename);
	return 0;
}
