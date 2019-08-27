#ifndef QEMU_DISAS_H
#define QEMU_DISAS_H

#include "qemu-common.h"

#ifdef NEED_CPU_H
#include "cpu.h"

/* Disassemble this for me please... (debugging). */
void disas(FILE *out, void *code, unsigned long size);
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size);

void monitor_disas(Monitor *mon, CPUState *cpu,
                   target_ulong pc, int nb_insn, int is_physical);

/* Look up symbol for debugging purpose.  Returns "" if unknown. */
const char *lookup_symbol(target_ulong orig_addr);
bool lookup_symbol2(target_ulong orig_addr, const char **symbol, const char **filename);
bool lookup_symbol3(target_ulong orig_addr, const char **symbol, const char **filename, uint64_t *address);
bool lookup_symbol4(target_ulong orig_addr, const char **symbol, const char **filename, uint64_t *address, uint64_t *size);
bool lookup_symbol5(target_ulong orig_addr, const char **symbol, const char **filename, uint64_t *address, uint64_t *size, uint64_t *load_bias);

/* Look up symbol bounds by name for debugging purpose.  Returns false if unknown. */
bool find_symbol_bounds(const char *name, bool is_elf_class64, uint64_t *start, uint64_t *size);
#endif

struct syminfo;
struct elf32_sym;
struct elf64_sym;

#if defined(CONFIG_USER_ONLY)
typedef const char *(*lookup_symbol_t)(struct syminfo *s, target_ulong orig_addr, target_ulong *symbol_addr, target_ulong *symbol_size);
#else
typedef const char *(*lookup_symbol_t)(struct syminfo *s, hwaddr orig_addr, hwaddr *symbol_addr, hwaddr *symbol_size);
#endif

struct syminfo {
    lookup_symbol_t lookup_symbol;
    unsigned int disas_num_syms;
    union {
      struct elf32_sym *elf32;
      struct elf64_sym *elf64;
    } disas_symtab;
    const char *disas_strtab;
    const char *filename;
    size_t load_bias;
    struct syminfo *next;
};

/* Filled in by elfload.c.  Simplistic, but will do for now. */
extern struct syminfo *syminfos;
extern uint64_t find_symbol(const char *name, int is_elf_class64);

#endif /* QEMU_DISAS_H */
