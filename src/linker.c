#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "elf_format.h"

#define MAX_INPUT_FILES 32
#define MAX_PLACEMENTS 32
#define MAX_SECTIONS 128
#define MAX_SECTIONS_PER_OBJECT 128
#define MAX_OBJECT_FILES 64

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

static Section sections[MAX_SECTIONS];
static size_t section_count = 0;

typedef struct {
    Symbol symbols[MAX_SYMBOLS];
    size_t symbol_count;
    Relocation relocations[MAX_RELOCATIONS];
    size_t reloc_count;
    size_t section_global_index[MAX_SECTIONS_PER_OBJECT];
    size_t section_offset_in_global[MAX_SECTIONS_PER_OBJECT];
    size_t section_count;
} ObjectFile;

static ObjectFile object_files[MAX_OBJECT_FILES];
static size_t object_file_count = 0;

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
	for(size_t i = 0; i < object_file_count; i++) {
		ObjectFile* of = &object_files[i];
		for(size_t i = 0; i < of ->symbol_count; i++) {
			Symbol* sym = &of->symbols[i];
			if(sym->global && strcmp(sym->name, name) == 0) {
				return sym;
			}
		}
	}
    return NULL;
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

static void read_exact(FILE *f, void *buf, size_t sz) {
    if(fread(buf, 1, sz, f) != sz) {
        fprintf(stderr, "Error: Failed to read data\n");
		exit(1);
    }
}

void load_sections(const LinkerOptions *opts, FILE *f, ObjectFile *of) {
    typedef struct {
        char name[64];
        uint32_t addr;
    } Cursor;

    Cursor cursors[MAX_SECTIONS];
    int cursor_count = 0;

    uint32_t sec_count;
    read_exact(f, &sec_count, sizeof(sec_count));

    for (uint32_t i = 0; i < sec_count; i++) {
        char name[64];
        read_exact(f, name, sizeof(name));
        name[63] = '\0';

        uint64_t size64;
        read_exact(f, &size64, sizeof(size64));
        size_t size = (size_t)size64;

        unsigned char *data = NULL;
        if (size) {
            data = malloc(size);
            if (!data) {
                fprintf(stderr, "Error: malloc failed for section %s\n", name);
                exit(1);
            }
            read_exact(f, data, size);
        }

        uint32_t addr = 0;
        int found = 0;

        for (int p = 0; p < opts->placement_count; p++) {
            if (strcmp(opts->placements[p].section_name, name) == 0) {
                addr = opts->placements[p].address;
                found = 1;
                break;
            }
        }
        if (!found) {
            for (int c = 0; c < cursor_count; c++) {
                if (strcmp(cursors[c].name, name) == 0) {
                    addr = cursors[c].addr;
                    found = 1;
                    break;
                }
            }
        }
        if (!found && cursor_count < MAX_SECTIONS) {
            strncpy(cursors[cursor_count].name, name, 63);
            cursors[cursor_count].name[63] = '\0';
            cursors[cursor_count].addr = 0;
            cursor_count++;
        }

        Section *s = find_section(name);
        size_t local_off = 0;
        size_t global_idx;

        if (s) {
            local_off = s->size;
            unsigned char *new_data = realloc(s->data, s->size + size);
            if (!new_data) {
                fprintf(stderr, "Error: realloc failed for section %s\n", name);
                exit(1);
            }
            s->data = new_data;
            if (size) memcpy(s->data + local_off, data, size);
            s->size += size;
            s->capacity = s->size;
            free(data);
        } else {
            if (section_count >= MAX_SECTIONS) {
                fprintf(stderr, "Error: Too many sections\n");
                exit(1);
            }
            s = &sections[section_count++];
            memset(s, 0, sizeof(*s));
            strncpy(s->name, name, 63);
            s->name[63] = '\0';
            s->size = s->capacity = size;
            s->data = data;
            s->base = addr;
        }
        global_idx = (size_t)(s - sections);

        for (int c = 0; c < cursor_count; c++) {
            if (strcmp(cursors[c].name, name) == 0) {
                cursors[c].addr = s->base + s->size;
                break;
            }
        }

        if (of->section_count >= MAX_SECTIONS_PER_OBJECT) {
            fprintf(stderr, "Error: too many sections in object\n");
            exit(1);
        }
        of->section_global_index[of->section_count] = global_idx;
        of->section_offset_in_global[of->section_count++] = local_off;
    }
}

void load_symbols(FILE *f, ObjectFile *of) {
    uint32_t sym_count;
    read_exact(f, &sym_count, sizeof(sym_count));

    if (sym_count > MAX_SYMBOLS) {
        fprintf(stderr, "Error: Too many symbols (%u > %u)\n", sym_count, MAX_SYMBOLS);
        exit(1);
    }

    for (uint32_t i = 0; i < sym_count; i++) {
        if (of->symbol_count >= MAX_SYMBOLS) {
            fprintf(stderr, "Error: too many local symbols\n");
            exit(1);
        }

        Symbol *dst = &of->symbols[of->symbol_count++];
        memset(dst, 0, sizeof(*dst));

        uint32_t name_len;
        read_exact(f, &name_len, sizeof(name_len));
        dst->name = malloc(name_len + 1);
        read_exact(f, dst->name, name_len);
        dst->name[name_len] = '\0';

        uint64_t off;
        read_exact(f, &off, sizeof(off));
        dst->offset = (size_t)off;

        uint32_t sec_len;
        read_exact(f, &sec_len, sizeof(sec_len));
        if (sec_len > 0) {
            dst->section = malloc(sec_len + 1);
            read_exact(f, dst->section, sec_len);
            dst->section[sec_len] = '\0';
        }

        uint8_t b[4];
        read_exact(f, b, sizeof(b));
        dst->defined = !!b[0];
        dst->global = !!b[1];
        dst->external = !!b[2];
        dst->relocatable = !!b[3];
    }
}

void load_relocations(FILE* f, ObjectFile *of) {
    uint32_t reloc_cnt;
    read_exact(f, &reloc_cnt, sizeof(reloc_cnt));
    if (reloc_cnt > MAX_RELOCATIONS) {
        fprintf(stderr, "Error: Too many relocations\n");
		exit(1);
    }

    for (uint32_t i = 0; i < reloc_cnt; i++) {
        if (of->reloc_count >= MAX_RELOCATIONS) {
            fprintf(stderr, "Error: too many relocations\n");
			exit(1);
        }
        Relocation *rel = &of->relocations[of->reloc_count++];
        memset(rel, 0, sizeof(Relocation));

        uint32_t sec_len;
        read_exact(f, &sec_len, sizeof(sec_len));
        char *sec_name = sec_len ? malloc(sec_len + 1) : NULL;
        if (sec_name) {
            read_exact(f, sec_name, sec_len);
            sec_name[sec_len] = '\0';
            rel->section = find_section(sec_name);
            free(sec_name);
        }

        if (!rel->section) {
            fprintf(stderr, "Error: Relocation references unknown section\n");
			exit(1);
        }

        uint64_t offset;
        read_exact(f, &offset, sizeof(offset));
        rel->offset = (size_t)offset;

        uint32_t sym_len;
        read_exact(f, &sym_len, sizeof(sym_len));
        rel->symbol = malloc(sym_len + 1);
        read_exact(f, rel->symbol, sym_len);
        rel->symbol[sym_len] = '\0';

        uint32_t type;
        read_exact(f, &type, sizeof(type));
        rel->type = (RelocType)type;
    }
}

void load_input_files(const LinkerOptions *opts) {
	for (int i = 0; i < opts->input_count; i++) {
		const char *filename = opts->input_files[i];

		if (object_file_count >= MAX_OBJECT_FILES) {
			fprintf(stderr, "Error: too many object files\n");
			exit(1);
		}

		FILE *f = fopen(filename, "rb");
		if (!f) {
			fprintf(stderr, "Error: Cannot open file %s\n", filename);
		}

		ObjectFile *of = &object_files[object_file_count++];
		memset(of, 0, sizeof(ObjectFile));

		load_sections(opts, f, of);
		load_symbols(f, of);
		load_relocations(f, of);

		fclose(f);
	}
}

void resolve_symbols() {
    for (size_t fi = 0; fi < object_file_count; fi++) {
        ObjectFile *of = &object_files[fi];

        for (size_t si = 0; si < of->symbol_count; si++) {
            Symbol *sym = &of->symbols[si];

            if (sym->relocatable && sym->section) {
                for (size_t sgi = 0; sgi < of->section_count; sgi++) {
                    Section *s = &sections[of->section_global_index[sgi]];
                    if (!strcmp(s->name, sym->section)) {
                        sym->offset += s->base + of->section_offset_in_global[sgi];
                        break;
                    }
                }
            }
        }
    }

    for (size_t fi = 0; fi < object_file_count; fi++) {
        ObjectFile *of = &object_files[fi];

        for (size_t si = 0; si < of->symbol_count; si++) {
            Symbol *sym = &of->symbols[si];

            if (sym->external && !sym->defined) {
                Symbol *resolved = find_symbol(sym->name);

                if (!resolved || !resolved->defined) {
                    fprintf(stderr, "Linker error: undefined external symbol '%s'\n", sym->name);
                    exit(1);
                }

                sym->offset = resolved->offset;
                if (sym->section) {
                    free(sym->section);
                }
                sym->section = resolved->section ? strdup(resolved->section) : NULL;
                sym->defined = true;
            }
        }
    }
}

void resolve_relocations() {
	for (size_t of_i = 0; of_i < object_file_count; of_i++) {
		ObjectFile *of = &object_files[of_i];

		for (size_t ri = 0; ri < of->reloc_count; ri++) {
			Relocation *rel = &of->relocations[ri];
			if (!rel->section || !rel->symbol) {
				fprintf(stderr, "Error: Relocation %zu in object %zu has invalid section or symbol\n", ri, of_i);
				exit(1);
			}

			Symbol *target = NULL;
			for (size_t si = 0; si < of->symbol_count; si++) {
				if (strcmp(of->symbols[si].name, rel->symbol) == 0) {
					target = &of->symbols[si];
					break;
				}
			}

			if (!target || !target->defined) {
				fprintf(stderr, "Error: Undefined symbol in relocation: %s\n", rel->symbol);
				exit(1);
			}

			Section *sec = rel->section;
			size_t section_local_offset = 0;
			for (size_t i = 0; i < of->section_count; i++) {
				if (&sections[of->section_global_index[i]] == sec) {
					section_local_offset = of->section_offset_in_global[i];
					break;
				}
			}

			size_t offset = rel->offset + section_local_offset;
			if (offset + 4 > sec->size) {
				fprintf(stderr, "Error: Relocation offset out of bounds in section %s\n", sec->name);
				exit(1);
			}

			uint32_t addr = target->offset;

			if (rel->type == RELOC_ABS) {
				sec->data[offset + 0] |= (addr >> 24) & 0xFF;
				sec->data[offset + 1] |= (addr >> 16) & 0xFF;
				sec->data[offset + 2] |= (addr >> 8) & 0xFF;
				sec->data[offset + 3] |= (addr >> 0) & 0xFF;
			} else if (rel->type == RELOC_PC_REL) {
				size_t instr = (offset >= 2) ? offset - 2 : 0;
				uint32_t pc = (uint32_t)instr + 4;
				uint32_t rel_val = addr - pc + section_local_offset;
				uint32_t orig = (sec->data[instr + 0] << 24) | (sec->data[instr + 1] << 16)
					| (sec->data[instr + 2] << 8) | sec->data[instr + 3];
				uint32_t patched = orig | rel_val;
				sec->data[instr + 0] = (patched >> 24) & 0xFF;
				sec->data[instr + 1] = (patched >> 16) & 0xFF;
				sec->data[instr + 2] = (patched >> 8) & 0xFF;
				sec->data[instr + 3] = (patched >> 0) & 0xFF;
			}
		}
	}
}

void assign_section_bases(const LinkerOptions *opts) {
    bool assigned[MAX_SECTIONS] = { false };

    for (int i = 0; i < opts->placement_count; i++) {
        const char *placement_name = opts->placements[i].section_name;

        for (size_t j = 0; j < section_count; j++) {
            Section *s = &sections[j];
            if (strcmp(s->name, placement_name) == 0) {
                assigned[j] = true;
            }
        }
    }

    for (size_t i = 0; i < section_count; i++) {
        if (!assigned[i]) continue;

        for (size_t j = i + 1; j < section_count; j++) {
            if (!assigned[j]) continue;
            Section *a = &sections[i];
            Section *b = &sections[j];
            size_t a_end = (size_t)a->base + a->size;
            size_t b_end = (size_t)b->base + b->size;
            if ((a->base < b_end && a_end > b->base)) {
                fprintf(stderr, "Linker error: sections '%s' and '%s' overlap (0x%lX ~ 0x%lX)\n",
                        a->name, b->name,
                        (unsigned long)((a->base < b->base) ? a->base : b->base),
                        (unsigned long)((a_end > b_end) ? a_end : b_end));
                exit(1);
            }
        }
    }

    size_t next_base = 0;
    for (size_t i = 0; i < section_count; i++) {
        if (assigned[i]) continue;
        Section *s = &sections[i];
        while (1) {
            bool conflict = false;
            for (size_t j = 0; j < section_count; j++) {
                if (i == j) continue;
                Section *other = &sections[j];
                if (!assigned[j] && other->base == 0) continue;
                size_t o_start = other->base;
                size_t o_end = (size_t)other->base + other->size;
                if (!(next_base + s->size <= o_start || next_base >= o_end)) {
                    next_base = o_end;
                    conflict = true;
                    break;
                }
            }

            if (!conflict) break;
        }
        s->base = next_base;
        assigned[i] = true;
        next_base += s->size;
    }
}

void write_output(LinkerOptions *opts) {
	FILE *f = fopen(opts->output_filename, opts->hex_output ? "w" : "wb");
	if (!f) {
		fprintf(stderr, "Error: Cannot open output file %s\n", opts->output_filename);
		exit(1);
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
}

int main(int argc, char **argv) {
	LinkerOptions opts;
	if (!parse_args(argc, argv, &opts)) {
		print_usage();
		return 1;
	}

	load_input_files(&opts);
	assign_section_bases(&opts);
	resolve_symbols();
	resolve_relocations();
	write_output(&opts);

	return 0;
}
