/*
 * TCG plugin for QEMU: count the number of executed instructions per
 *                      CPU.
 *
 * Copyright (C) 2011 STMicroelectronics
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include "tcg-plugin.h"
#include "disas/disas.h"

/* glib must be included after osdep.h (which we include transitively via tcg-plugin.h) */
#include <glib.h>

#ifdef CONFIG_CAPSTONE
#include <capstone/capstone.h>
/* Check compatibility with capstone 3.x. */
#if CS_API_MAJOR < 3
#error "dyncount plugin required capstone library >= 3.x. Please install from http://www.capstone-engine.org/."
#endif

#if defined(TARGET_X86_64)
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_64
#define CS_GROUPS_NAME "x86"
#define CS_INS_COUNT X86_INS_ENDING
#define CS_GRP_COUNT X86_GRP_ENDING
#elif defined(TARGET_I386)
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_32
#define CS_GROUPS_NAME "x86"
#define CS_INS_COUNT X86_INS_ENDING
#define CS_GRP_COUNT X86_GRP_ENDING
#elif defined(TARGET_AARCH64)
#define CS_ARCH CS_ARCH_ARM64
#define CS_MODE 0
#define CS_GROUPS_NAME "arm64"
#define CS_INS_COUNT ARM64_INS_ENDING
#define CS_GRP_COUNT ARM64_GRP_ENDING
#elif defined(TARGET_ARM)
#define CS_ARCH CS_ARCH_ARM
#define CS_MODE CS_MODE_ARM
#define CS_GROUPS_NAME "arm"
#define CS_INS_COUNT ARM_INS_ENDING
#define CS_GRP_COUNT ARM_GRP_ENDING
#else
#define CS_GROUPS_NAME ""
#endif
#define INS_MAX_COUNT 4096
#define GRP_MAX_COUNT 4096

#endif /* CONFIG_CAPSTONE */

#if !defined(CONFIG_CAPSTONE) || !defined(CS_ARCH)
void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
#if !defined(CONFIG_CAPSTONE)
    fprintf(tpi->output,
            "# WARNING: dyncount plugin disabled.\n"
            "#          capstone library >= 3.x was not found when configuring QEMU.\n"
            "#          Install capstone from http://www.capstone-engine.org/\n"
            "#          and reconfigure/recompile QEMU.\n"
        );
#elif !defined(CS_ARCH)
    fprintf(tpi->output,
            "# WARNING: dyncount plugin disabled.\n"
            "           This plugin is not available for target " TARGET_NAME ".\n"
        );
#endif
}
#else

/* Maintains information for a recorded mnemonic or group string. */
typedef struct
{
    const char *name; /* Name, used as key. */
    int serial_idx;  /* Unique dense idx into op_count/group_count array. */
    int cs_idx;      /* Capstone op/grp idx. */
} str_hash_entry_t;


/* Global capstone handle. Not synchronized. */
static csh cs_handle;

/* Shared globals. Must be synchrionized. */
static int op_current_idx;
static uint64_t op_count[INS_MAX_COUNT];
static GHashTable *op_hash;
static str_hash_entry_t *op_entries[INS_MAX_COUNT];
static int grp_current_idx;
static uint64_t grp_count[GRP_MAX_COUNT];
static GHashTable *grp_hash;
static str_hash_entry_t *grp_entries[INS_MAX_COUNT];
static uint64_t ld_bytes;
static uint64_t st_bytes;

static void free_str_hash_entry(gpointer data)
{
  str_hash_entry_t *entry = (str_hash_entry_t *)data;
  g_free((gpointer)entry->name);
  g_free(entry);
}

static int cmp_str_hash_entry_ptr(const void *a, const void *b)
{
    return strcmp((*(const str_hash_entry_t **)a)->name,
                  (*(const str_hash_entry_t **)b)->name);
}


static void cpus_stopped(const TCGPluginInterface *tpi)
{
    int i;
    uint64_t icount_total = 0;

    qsort(&op_entries[0], op_current_idx, sizeof(str_hash_entry_t *),
          cmp_str_hash_entry_ptr);
    qsort(&grp_entries[0], grp_current_idx, sizeof(str_hash_entry_t *),
          cmp_str_hash_entry_ptr);

    fprintf(tpi->output, "\nmnemonics_count:\n");
    for (i = 0; i < op_current_idx; i++) {
        fprintf(tpi->output,
                "  %s: %"PRIu64"\n",
                op_entries[i]->name,
                op_count[op_entries[i]->serial_idx]);
        icount_total += op_count[i];
    }
    fprintf(tpi->output, "\ngroups_count:\n");
    for (i = 0; i < grp_current_idx; i++) {
        fprintf(tpi->output,
                "  %s: %"PRIu64"\n",
                grp_entries[i]->name,
                grp_count[grp_entries[i]->serial_idx]);
    }
    fprintf(tpi->output, "\nloaded_bytes: %"PRIu64"\n", ld_bytes);
    fprintf(tpi->output, "\nstored_bytes: %"PRIu64"\n", st_bytes);
    fprintf(tpi->output, "\ninstructions_total: %"PRIu64"\n", icount_total);
    fflush(tpi->output);
    g_hash_table_destroy(op_hash);
    g_hash_table_destroy(grp_hash);

}

static void update_counter(uint64_t counter_ptr, uint64_t count)
{
    atomic_add((uint64_t *)counter_ptr, count);
}

static void gen_update_counter(const TCGPluginInterface *tpi, uint64_t *counter_ptr, uint64_t count)
{
    TCGTemp *args[3];
    TCGv_i64 tcgv_counter_ptr;
    TCGv_i64 tcgv_count;

    tcgv_counter_ptr = tcg_const_i64((uint64_t)(intptr_t)counter_ptr);
    tcgv_count = tcg_const_i64(1);

    args[0] = tcgv_i64_temp(tcgv_counter_ptr);
    args[1] = tcgv_i64_temp(tcgv_count);

    tcg_gen_callN(update_counter, TCG_CALL_DUMMY_ARG, 2, args);

    tcg_temp_free_i64(tcgv_counter_ptr);
    tcg_temp_free_i64(tcgv_count);
}

static int insert_op_entry(const char *op_name, int cs_op_idx)
{
    /* Called from translation only, no need to synchronize. */
    str_hash_entry_t *op_entry;

    op_entry =
        g_hash_table_lookup(op_hash, op_name);
    if (op_entry == NULL) {
        assert(op_current_idx < INS_MAX_COUNT);
        op_entry = g_new(str_hash_entry_t, 1);
        op_entry->name = g_strdup(op_name);
        op_entry->serial_idx = op_current_idx;
        op_entry->cs_idx = cs_op_idx;
        g_hash_table_insert(op_hash,
                            (gpointer)op_entry->name,
                            op_entry);
        op_entries[op_current_idx] = op_entry;
        op_current_idx++;
    }
    return op_entry->serial_idx;
}

static int insert_grp_entry(const char *grp_name, int cs_grp_idx)
{
    str_hash_entry_t *grp_entry;

    grp_entry =
        g_hash_table_lookup(grp_hash, grp_name);
    if (grp_entry == NULL) {
        assert(grp_current_idx < INS_MAX_COUNT);
        grp_entry = g_new(str_hash_entry_t, 1);
        grp_entry->name = g_strdup(grp_name);
        grp_entry->serial_idx = grp_current_idx;
        grp_entry->cs_idx = cs_grp_idx;
        g_hash_table_insert(grp_hash,
                            (gpointer)grp_entry->name,
                            grp_entry);
        grp_entries[grp_current_idx] = grp_entry;
        grp_current_idx++;
    }
    return grp_entry->serial_idx;
}

static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    size_t count;
    cs_insn *insns;

    switch(tpi_opcode->operator) {
    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        gen_update_counter(tpi, &ld_bytes,
                           1 << (get_memop(tpi_opcode->opargs[2]) & MO_SIZE));
        return;

    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st_i64:
        gen_update_counter(tpi, &st_bytes,
                           1 << (get_memop(tpi_opcode->opargs[2]) & MO_SIZE));
        return;
    case INDEX_op_insn_start:
        break;
    default:
        return;
    }

    count = cs_disasm(cs_handle, (void *)(intptr_t)tpi_guest_ptr(tpi, tpi_opcode->pc), 16,
                      tpi_opcode->pc, 1, &insns);
    if (count > 0) {
        cs_insn *insn = &insns[0];
        cs_detail *detail = insn->detail;
        int serial_idx = insert_op_entry(insn->mnemonic, insn->id);
        gen_update_counter(tpi, &op_count[serial_idx], 1);
        if (detail->groups_count > 0) {
            int n;
            for (n = 0; n < detail->groups_count; n++) {
                int group = detail->groups[n];
                int serial_idx;
                assert(group < CS_GRP_COUNT);
                serial_idx = insert_grp_entry(cs_group_name(cs_handle, group), group);
                gen_update_counter(tpi, &grp_count[serial_idx], 1);
            }
        } else {
            /* If not in any group, add to group 0 (nogroup). */
            int serial_idx = insert_grp_entry("nogroup", 0);
            gen_update_counter(tpi, &grp_count[serial_idx], 1);
        }
        cs_free(insn, count);
    } else {
        const char *symbol, *filename;
        uint64_t address;
        lookup_symbol3(tpi_opcode->pc, &symbol, &filename, &address);
        fprintf(tpi->output, "# WARNING: tcg/plugins/dyncount: unable to disassemble instruction at PC 0x%"PRIx64" (%s: %s + 0x%"PRIx64")\n", tpi_opcode->pc, filename, symbol, tpi_opcode->pc - address);
        int serial_op_idx = insert_op_entry("_unknown_", 0);
        int serial_grp_idx = insert_op_entry("nogroup", 0);
        gen_update_counter(tpi, &op_count[serial_op_idx], 1);
        gen_update_counter(tpi, &grp_count[serial_grp_idx], 1);
    }
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
    TPI_DECL_FUNC_2(tpi, update_counter, void, i64, i64);

    if (cs_open(CS_ARCH, CS_MODE, &cs_handle) != CS_ERR_OK)
        abort();

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    tpi->cpus_stopped = cpus_stopped;
    tpi->after_gen_opc = after_gen_opc;

    op_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                                    free_str_hash_entry);
    grp_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                                     free_str_hash_entry);
}

#endif /* CONFIG_CAPSTONE */
