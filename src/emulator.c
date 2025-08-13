#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <sys/select.h>

#define TERM_OUT_ADDR    0xFFFFFF00u
#define TERM_IN_ADDR     0xFFFFFF04u
#define TIM_CFG_ADDR     0xFFFFFF10u

#define PAGE_BITS   12
#define PAGE_SIZE   (1 << PAGE_BITS)
#define NUM_PAGES   (1u << (32 - PAGE_BITS))

typedef struct {
    uint8_t *pages[NUM_PAGES];
} Memory;

void mem_init(Memory *mem) {
    memset(mem->pages, 0, sizeof(mem->pages));
}

static inline uint8_t* get_page(Memory *mem, uint32_t addr, int create) {
    uint32_t page_index = addr >> PAGE_BITS;
    uint8_t *p = mem->pages[page_index];
    if (!p && create) {
        p = calloc(1, PAGE_SIZE);
        if (!p) return NULL;
        mem->pages[page_index] = p;
    }
    return p;
}

typedef struct {
    uint32_t r[16];
    uint32_t csr[3];

    uint32_t *pc;
    uint32_t *sp;

    uint32_t *status;
    uint32_t *handler;
    uint32_t *cause;
} CPUState;

typedef struct {
    Memory *mem;
    CPUState cpu;

    atomic_int pending_interrupt;
    atomic_int pending_cause;
    pthread_mutex_t mem_lock;

    struct termios orig_tios;
    atomic_int term_has_char;
    atomic_uint term_char;

    atomic_uint tim_cfg;

    atomic_int running;
} System;

void term_printf(const char *fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len > 0) {
        write(STDOUT_FILENO, buf, len);
    }
}

uint8_t sys_mem_read8(System *sys, uint32_t addr) {
    if (addr == TERM_IN_ADDR) {
        if (atomic_load(&sys->term_has_char)) {
            unsigned int c = atomic_load(&sys->term_char);
            atomic_store(&sys->term_has_char, 0);
            return (uint8_t)c;
        } else {
            return 0;
        }
    }
    if (addr == TERM_OUT_ADDR) {
        return 0;
    }
    if (addr == TIM_CFG_ADDR) {
        return (uint8_t)(atomic_load(&sys->tim_cfg) & 0xFFu);
    }

    pthread_mutex_lock(&sys->mem_lock);
    uint8_t *page = get_page(sys->mem, addr, 0);
    uint8_t v = 0;
    if (page) {
        v = page[addr & (PAGE_SIZE - 1)];
    }
    pthread_mutex_unlock(&sys->mem_lock);
    return v;
}

void sys_mem_write8(System *sys, uint32_t addr, uint8_t val) {
    if (addr == TERM_OUT_ADDR) {
		term_printf("%c", (char)val);
        return;
    }
    if (addr == TERM_IN_ADDR) {
        atomic_store(&sys->term_char, (unsigned int)val);
        atomic_store(&sys->term_has_char, 1);
        atomic_store(&sys->pending_cause, 3);
        atomic_store(&sys->pending_interrupt, 1);
        return;
    }
    if (addr == TIM_CFG_ADDR) {
        atomic_store(&sys->tim_cfg, (unsigned int)(val & 0x7u));
        return;
    }

    pthread_mutex_lock(&sys->mem_lock);
    uint8_t *page = get_page(sys->mem, addr, 1);
    if (!page) {
        fprintf(stderr, "Out of memory allocating page for addr 0x%08x\n", addr);
        pthread_mutex_unlock(&sys->mem_lock);
        return;
    }
    page[addr & (PAGE_SIZE - 1)] = val;
    pthread_mutex_unlock(&sys->mem_lock);
}

uint32_t sys_mem_read32(System *sys, uint32_t addr) {
    if (addr == TERM_IN_ADDR) {
        uint32_t val = 0;
        if (atomic_load(&sys->term_has_char)) {
            unsigned int c = atomic_load(&sys->term_char);
            atomic_store(&sys->term_has_char, 0);
            val = (uint8_t)c;
        }
        return val;
    }
    if (addr == TERM_OUT_ADDR) {
        return 0;
    }
    if (addr == TIM_CFG_ADDR) {
        return atomic_load(&sys->tim_cfg) & 0x7u;
    }

    pthread_mutex_lock(&sys->mem_lock);
    uint8_t *page = get_page(sys->mem, addr, 0);
    uint32_t v = 0;
    if (page) {
        uint32_t offset = addr & (PAGE_SIZE - 1);
        if (offset <= PAGE_SIZE - 4) {
            v = (page[offset + 0] << 24) |
                (page[offset + 1] << 16) |
                (page[offset + 2] << 8)  |
                (page[offset + 3] << 0);
        } else {
            v = (sys_mem_read8(sys, addr + 0) << 0)  |
                (sys_mem_read8(sys, addr + 1) << 8)  |
                (sys_mem_read8(sys, addr + 2) << 16) |
                (sys_mem_read8(sys, addr + 3) << 24);
            pthread_mutex_unlock(&sys->mem_lock);
            return v;
        }
    }
    pthread_mutex_unlock(&sys->mem_lock);
    return v;
}

void sys_mem_write32(System *sys, uint32_t addr, uint32_t val) {
    if (addr == TERM_OUT_ADDR) {
		term_printf("%c", (char)(val >> 24));
        return;
    }
    if (addr == TERM_IN_ADDR) {
        atomic_store(&sys->term_char, (unsigned int)(val & 0xFFu));
        atomic_store(&sys->term_has_char, 1);
        atomic_store(&sys->pending_cause, 3);
        atomic_store(&sys->pending_interrupt, 1);
        return;
    }
    if (addr == TIM_CFG_ADDR) {
        atomic_store(&sys->tim_cfg, (unsigned int)(val & 0x7u));
        return;
    }

    uint8_t b3 = (uint8_t)(val & 0xFFu);
    uint8_t b2 = (uint8_t)((val >> 8) & 0xFFu);
    uint8_t b1 = (uint8_t)((val >> 16) & 0xFFu);
    uint8_t b0 = (uint8_t)((val >> 24) & 0xFFu);
    sys_mem_write8(sys, addr + 0, b0);
    sys_mem_write8(sys, addr + 1, b1);
    sys_mem_write8(sys, addr + 2, b2);
    sys_mem_write8(sys, addr + 3, b3);
}

void cpu_push(System *sys, uint32_t val) {
    *sys->cpu.sp -= 4;
    sys_mem_write32(sys, *sys->cpu.sp, val);
}

uint32_t cpu_pop(System *sys) {
    uint32_t val = sys_mem_read32(sys, *sys->cpu.sp);
    *sys->cpu.sp += 4;
    return val;
}

int load_hexfile(System *sys, const char *fname) {
    FILE *f = fopen(fname, "r");
    if (!f) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;

        char *endptr = NULL;
        unsigned long addr = strtoul(p, &endptr, 16);
        if (endptr == p) continue;
        p = endptr;

        while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;

        while (1) {
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '\0' || *p == '\n' || *p == '#') break;

            char *bend = NULL;
            unsigned long b = strtoul(p, &bend, 16);
            if (bend == p) break;

            if (addr <= 0xFFFFFFFFu) {
                sys_mem_write8(sys, (uint32_t)addr, (uint8_t)(b & 0xFFu));
            } else {
                fprintf(stderr, "Warning: skipping byte at out-of-range address 0x%lx\n", addr);
            }

            addr++;
            p = bend;
        }
    }

    fclose(f);
    return 0;
}

void raise_interrupt(System *sys, uint32_t cause) {
    atomic_store(&sys->pending_cause, (int)cause);
    atomic_store(&sys->pending_interrupt, 1);
}

void usleep_ms(long usec) {
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

void *terminal_thread(void *arg) {
    System *sys = (System *)arg;

    struct termios tios;
    tcgetattr(STDIN_FILENO, &tios);
    sys->orig_tios = tios;

    struct termios raw = tios;
    raw.c_lflag &= ~(ECHO | ICANON);

    tcsetattr(STDIN_FILENO, TCSANOW, &raw);

    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    while (atomic_load(&sys->running)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        struct timeval tv = {0, 100000};
        int rv = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
        if (rv > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
            char c;
            ssize_t r = read(STDIN_FILENO, &c, 1);
            if (r == 1) {
                write(STDOUT_FILENO, &c, 1);

                atomic_store(&sys->term_char, (unsigned int)(uint8_t)c);
                atomic_store(&sys->term_has_char, 1);
                raise_interrupt(sys, 3);
            }
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &sys->orig_tios);
    return NULL;
}

unsigned int cfg_to_ms(unsigned int cfg) {
    switch (cfg & 0x7u) {
        case 0: return 500;
        case 1: return 1000;
        case 2: return 1500;
        case 3: return 2000;
        case 4: return 5000;
        case 5: return 10000;
        case 6: return 30000;
        case 7: return 60000;
        default: return 1000;
    }
}

void *timer_thread(void *arg) {
    System *sys = (System *)arg;
    while (atomic_load(&sys->running)) {
        unsigned int cfg = atomic_load(&sys->tim_cfg);
        unsigned int ms = cfg_to_ms(cfg);
        unsigned int slept = 0;
        while (slept < ms && atomic_load(&sys->running)) {
            unsigned int step = (ms - slept > 200) ? 200 : (ms - slept);
            usleep_ms(step * 1000);
            slept += step;
        }
        if (!atomic_load(&sys->running)) break;
        raise_interrupt(sys, 2);
    }
    return NULL;
}

void cpu_handle_interrupt(System *sys) {
    int pending = atomic_load(&sys->pending_interrupt);
    if (!pending) return;
    uint32_t cause = (uint32_t)atomic_load(&sys->pending_cause);

    uint32_t status = *sys->cpu.status;
    int I  = (status & 0x1u) ? 1:0;
    int Tl = (status & 0x2u) ? 1:0;
    int Tr = (status & 0x4u) ? 1:0;

    int allowed = 0;
    if (cause == 2) {
        if (!I && !Tr) allowed = 1;
    } else if (cause == 3) {
        if (!I && !Tl) allowed = 1;
    } else {
        if (!I) allowed = 1;
    }

    if (!allowed) return;

    uint32_t sp = sys->cpu.r[14];
    sp -= 4;
    sys_mem_write32(sys, sp, *sys->cpu.status);
    sp -= 4;
    sys_mem_write32(sys, sp, sys->cpu.r[15]);
    sys->cpu.r[14] = sp;

    *sys->cpu.cause = cause;
    *sys->cpu.status |= 0x1u;
    sys->cpu.r[15] = *sys->cpu.handler;

    atomic_store(&sys->pending_interrupt, 0);
}

void cpu_init(System *sys) {
    memset(&sys->cpu, 0, sizeof(sys->cpu));

    sys->cpu.pc = &sys->cpu.r[15];
    sys->cpu.sp = &sys->cpu.r[14];
    sys->cpu.status = &sys->cpu.csr[0];
    sys->cpu.handler = &sys->cpu.csr[1];
    sys->cpu.cause = &sys->cpu.csr[2];

    *sys->cpu.pc = 0x40000000;
    *sys->cpu.sp = 0xFFFFFFFF - 4;
    *sys->cpu.status = 0;
    *sys->cpu.handler = 0;
    *sys->cpu.cause = 0;
}

static void execute_instruction(System *sys, uint32_t instr) {
    uint32_t opcode = (instr >> 28) & 0xF;
    uint32_t mmmm = (instr >> 24) & 0xF;
    uint32_t a = (instr >> 20) & 0xF;
    uint32_t b = (instr >> 16) & 0xF;
    uint32_t c = (instr >> 12) & 0xF;
	int32_t d = (int32_t)(instr << 20) >> 20;

    switch (opcode) {
        case 0x0:
            if (instr == 0x00000000u) {
				printf("\n\n===========================================================\n");
    			for (int i = 0; i < 16; i++) {
        			printf("r%-2d=0x%08x", i, sys->cpu.r[i]);
        			if ((i % 4) == 3) printf("\n");
        			else printf(" ");
    			}
				exit(0);
            }
            break;
        case 0x1:
			cpu_push(sys, *sys->cpu.status);
			cpu_push(sys, *sys->cpu.pc);
			*sys->cpu.cause = 4;
			*sys->cpu.status = (*sys->cpu.status) & (~0x1);
			*sys->cpu.pc = *sys->cpu.handler;
            break;
        case 0x2:
            switch (mmmm) {
                case 0x0:
					cpu_push(sys, *sys->cpu.pc);
					*sys->cpu.pc = sys->cpu.r[a] + sys->cpu.r[b] + d;
                    break;
                case 0x1:
					cpu_push(sys, *sys->cpu.pc);
					*sys->cpu.pc = sys_mem_read32(sys, sys->cpu.r[a] + sys->cpu.r[b] + d);
                    break;
                default:
					raise_interrupt(sys, 1);
            }
            break;
		case 0x3:
		    switch (mmmm) {
		        case 0x0:
					*sys->cpu.pc = sys->cpu.r[a] + d;
					break;
		        case 0x1:
					if(sys->cpu.r[b] == sys->cpu.r[c]) *sys->cpu.pc = sys->cpu.r[a] + d;
					break;
		        case 0x2:
					if(sys->cpu.r[b] != sys->cpu.r[c]) *sys->cpu.pc = sys->cpu.r[a] + d;
					break;
		        case 0x3:
					if((int32_t)sys->cpu.r[b] > (int32_t)sys->cpu.r[c]) *sys->cpu.pc = sys->cpu.r[a] + d;
					break;
		        case 0x8:
					*sys->cpu.pc = sys_mem_read32(sys, sys->cpu.r[a] + d);
					break;
		        case 0x9:
					if(sys->cpu.r[b] == sys->cpu.r[c]) *sys->cpu.pc = sys_mem_read32(sys, sys->cpu.r[a] + d);
					break;
		        case 0xA:
					if(sys->cpu.r[b] != sys->cpu.r[c]) *sys->cpu.pc = sys_mem_read32(sys, sys->cpu.r[a] + d);
					break;
		        case 0xB:
					if((int32_t)sys->cpu.r[b] > (int32_t)sys->cpu.r[c]) *sys->cpu.pc = sys_mem_read32(sys, sys->cpu.r[a] + d);
					break;
		        default:
					raise_interrupt(sys, 1);
		    }
		    break;
        case 0x4: {
			uint32_t temp = sys->cpu.r[b];
			sys->cpu.r[b] = sys ->cpu.r[c];
			sys->cpu.r[c] = temp;
            break;
		}
        case 0x5:
            switch (mmmm) {
                case 0x0:
					sys->cpu.r[a] = sys->cpu.r[b] + sys->cpu.r[c];
					break;
                case 0x1:
					sys->cpu.r[a] = sys->cpu.r[b] - sys->cpu.r[c];
					break;
                case 0x2:
					sys->cpu.r[a] = sys->cpu.r[b] * sys->cpu.r[c];
					break;
                case 0x3:
					sys->cpu.r[a] = sys->cpu.r[b] / sys->cpu.r[c];
					break;
                default:
					raise_interrupt(sys, 1);
            }
            break;
        case 0x6:
            switch (mmmm) {
                case 0x0:
					sys->cpu.r[a] = ~sys->cpu.r[b];
					break;
                case 0x1:
					sys->cpu.r[a] = sys->cpu.r[b] & sys->cpu.r[c];
					break;
                case 0x2:
					sys->cpu.r[a] = sys->cpu.r[b] | sys->cpu.r[c];
					break;
                case 0x3:
					sys->cpu.r[a] = sys->cpu.r[b] ^ sys->cpu.r[c];
					break;
                default:
					raise_interrupt(sys, 1);
            }
            break;
        case 0x7:
            switch (mmmm) {
                case 0x0:
					sys->cpu.r[a] = sys->cpu.r[b] << sys->cpu.r[c];
					break;
                case 0x1:
					sys->cpu.r[a] = sys->cpu.r[b] >> sys->cpu.r[c];
					break;
                default:
					raise_interrupt(sys, 1);
            }
            break;
        case 0x8:
            switch (mmmm) {
                case 0x0: {
					uint32_t addr = sys->cpu.r[a] + sys->cpu.r[b] + d;
					sys_mem_write32(sys, addr, sys->cpu.r[c]);
					break;
				}
                case 0x2: {
					uint32_t addr = sys->cpu.r[a] + sys->cpu.r[b] + d;
					addr = sys_mem_read32(sys, addr);
					sys_mem_write32(sys, addr, sys->cpu.r[c]);
					break;
				}
                case 0x1: {
					sys->cpu.r[a] += d;
					uint32_t addr = sys->cpu.r[a];
					sys_mem_write32(sys, addr, sys->cpu.r[c]);
					break;
				}
                default:
					raise_interrupt(sys, 1);
            }
            break;
        case 0x9:
            switch (mmmm) {
                case 0x0:
					sys->cpu.r[a] = sys->cpu.csr[b];
					break;
                case 0x1:
					sys->cpu.r[a] = sys->cpu.r[b] + d;
					break;
                case 0x2:
					sys->cpu.r[a] = sys_mem_read32(sys, sys->cpu.r[b] + sys->cpu.r[c] + d);
					break;
                case 0x3:
					sys->cpu.r[a] = sys_mem_read32(sys, sys->cpu.r[b]);
					sys->cpu.r[b] += d;
					break;
                case 0x4:
					sys->cpu.csr[a] = sys->cpu.r[b];
					break;
                case 0x5:
					sys->cpu.csr[a] = sys->cpu.r[b] | d;
					break;
                case 0x6:
					sys->cpu.csr[a] = sys_mem_read32(sys, sys->cpu.r[b] + sys->cpu.r[c] + d);
					break;
                case 0x7:
					sys->cpu.csr[a] = sys_mem_read32(sys, sys->cpu.r[b]);
					sys->cpu.r[b] += d;
					break;
                default:
					raise_interrupt(sys, 1);
            }
            break;
        default:
			raise_interrupt(sys, 1);
    }
}

void cpu_run(System *sys) {
    while (atomic_load(&sys->running)) {
        uint32_t instr = sys_mem_read32(sys, *sys->cpu.pc);
        *sys->cpu.pc += 4;

        if (instr == 0xFFFFFFFFu) {
            atomic_store(&sys->running, 0);
            break;
        }

		execute_instruction(sys, instr);

        cpu_handle_interrupt(sys);
    }
}

void dump_memory8(uint32_t start, uint32_t end, System *sys) {
    for (uint32_t addr = start; addr < end; addr++) {
        if ((addr - start) % 16 == 0) {
            printf("%08X: ", addr);
        }
        printf("%02X ", sys_mem_read8(sys, addr));
        if ((addr - start) % 16 == 15) {
            printf("\n");
        }
    }
    printf("\n");
}

void dump_memory32(uint32_t start, uint32_t end, System *sys) {
    for (uint32_t addr = start; addr < end; addr+=4) {
        if ((addr - start) % 16 == 0) {
            printf("%08X: ", addr);
        }
        printf("%08X ", sys_mem_read32(sys, addr));
        if ((addr - start) % 16 == 12) {
            printf("\n");
        }
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <mem_content.hex>\n", argv[0]);
        return 1;
    }
    System sys;
    memset(&sys, 0, sizeof(sys));

    sys.mem = malloc(sizeof(Memory));
    if (!sys.mem) {
        perror("malloc mem");
        return 1;
    }
    mem_init(sys.mem);

    if (pthread_mutex_init(&sys.mem_lock, NULL) != 0) {
        perror("pthread_mutex_init");
        free(sys.mem);
        return 1;
    }

    atomic_store(&sys.pending_interrupt, 0);
    atomic_store(&sys.pending_cause, 0);
    atomic_store(&sys.term_has_char, 0);
    atomic_store(&sys.term_char, 0);
    atomic_store(&sys.tim_cfg, 0);
    atomic_store(&sys.running, 1);

    int r = load_hexfile(&sys, argv[1]);
    if (r != 0) {
        fprintf(stderr, "Failed to load memory file (%d)\n", r);
        free(sys.mem);
        return 2;
    }

    cpu_init(&sys);

	// mem_write32(&sys, 0x40000080, 0x12345678);

    // dump_memory32(0x00000000, 0x00000100, &sys);
    // dump_memory32(0x40000000, 0x40000100, &sys);

    pthread_t term_tid, tim_tid;
    if (pthread_create(&term_tid, NULL, terminal_thread, &sys) != 0) {
        perror("pthread_create term");
        free(sys.mem);
        return 1;
    }
    if (pthread_create(&tim_tid, NULL, timer_thread, &sys) != 0) {
        perror("pthread_create timer");
        atomic_store(&sys.running, 0);
        pthread_join(term_tid, NULL);
        free(sys.mem);
        return 1;
    }

    cpu_run(&sys);

    atomic_store(&sys.running, 0);
    pthread_join(term_tid, NULL);
    pthread_join(tim_tid, NULL);

    pthread_mutex_destroy(&sys.mem_lock);

    for (uint32_t i = 0; i < NUM_PAGES; ++i) {
        if (sys.mem->pages[i]) free(sys.mem->pages[i]);
    }
    free(sys.mem);

    return 0;
}
