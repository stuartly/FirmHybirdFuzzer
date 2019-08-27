/*
 * TCG plugin for QEMU: coverage plugin for QEMU
 *                      output each instruction with hit count
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
#include <inttypes.h>
#include "tcg-plugin.h"
#include "disas/disas.h"

#ifdef CONFIG_CAPSTONE
#include <capstone/capstone.h>
#if CS_API_MAJOR < 3 /* Check compatibility with capstone 3.x. */
#error "capstone library >= 3.x required"
#endif
#if defined(TARGET_X86_64)
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_64
#define CS_GROUPS_NAME "x86"
#elif defined(TARGET_I386)
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_32
#define CS_GROUPS_NAME "x86"
#elif defined(TARGET_AARCH64)
#define CS_ARCH CS_ARCH_ARM64
#define CS_MODE 0
#define CS_GROUPS_NAME "arm64"
#elif defined(TARGET_ARM)
#define CS_ARCH CS_ARCH_ARM
#define CS_MODE CS_MODE_ARM
#define CS_GROUPS_NAME "arm"
#else
#define CS_GROUPS_NAME ""
#define CS_ARCH CS_ARCH_ALL /* to change */
#define CS_MODE CS_MODE_LITTLE_ENDIAN /* to change */
#endif
#endif /* CONFIG_CAPSTONE */


#ifdef CONFIG_CAPSTONE

static FILE *output;

static bool no_colors;
static bool coveralls_output;

static csh cs_handle;

static cs_insn *insn;

static GHashTable *symbol_table; /* symbol -> address_table */

static GHashTable *address_table; /* instr address -> count */

struct symbol_table_entry
{
    uint64_t symbol_address;
    uint64_t symbol_size;
};

struct address_table_entry
{
    uint64_t count;
};

static void after_exec_opc(uint64_t count_ptr)
{
    (*(uint64_t *)count_ptr)++;
}

static void after_gen_opc(
    const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    const char *symbol = NULL;
    const char *filename = NULL;
    uint64_t symbol_address = 0;
    uint64_t symbol_size = 0;

    if (tpi_opcode->operator != INDEX_op_insn_start)
        return;

    // ignore unknown symbols
    if (!lookup_symbol4(
            tpi_opcode->pc, &symbol, &filename, &symbol_address, &symbol_size)
        || symbol[0] == '\0')
        return;

    struct symbol_table_entry *symbol_table_entry =
        g_hash_table_lookup(symbol_table, symbol);
    if (symbol_table_entry == NULL) {
        symbol_table_entry = g_new(struct symbol_table_entry, 1);
        symbol_table_entry->symbol_address = symbol_address;
        symbol_table_entry->symbol_size = symbol_size;
        g_hash_table_insert(symbol_table, g_strdup(symbol), symbol_table_entry);
    }

    uint64_t *address_table_key = (uint64_t *)tpi_opcode->pc;
    struct address_table_entry *address_table_entry = g_hash_table_lookup(
        address_table, address_table_key);
    if (address_table_entry == NULL) {
        address_table_entry = g_new(struct address_table_entry, 1);
        address_table_entry->count = 0;
        g_hash_table_insert(
            address_table, address_table_key, address_table_entry);
    }

    // insert call to after_exec_opc
    TCGTemp *args[] = {
        tcgv_i64_temp(tcg_const_i64((uint64_t)&address_table_entry->count)) };
    tcg_gen_callN(after_exec_opc, TCG_CALL_DUMMY_ARG, 1, args);
}

static void output_symbol_coverage(
    gpointer key, gpointer value, gpointer user_data)
{
    const char *symbol = (const char *)key;
    struct symbol_table_entry *symbol_entry = value;
    const TCGPluginInterface *tpi = (const TCGPluginInterface *)user_data;

    const uint8_t *code = (const uint8_t *)(intptr_t)tpi_guest_ptr(
        tpi, symbol_entry->symbol_address);
    size_t size = symbol_entry->symbol_size;
    uint64_t address = symbol_entry->symbol_address;

    if (coveralls_output) {
        fprintf(output, "\"%s\":\n", symbol);
        fprintf(output, "  - [ null, \"// symbol %s\" ]\n", symbol);
    } else
        fprintf(output, "// symbol %s\n", symbol);
    while (cs_disasm_iter(cs_handle, &code, &size, &address, insn)) {
        struct address_table_entry *value =
            g_hash_table_lookup(address_table, (uint64_t *)insn->address);
        uint64_t count = value ? value->count : 0;
        if (no_colors)
            fprintf(output, "%8" PRIu64 " | 0x%" PRIx64 ":\t %s\t %s\n",
                    count, insn->address, insn->mnemonic, insn->op_str);
        else if (coveralls_output)
            fprintf(output, "  - [ %" PRIu64 ", \"// 0x%"PRIx64":\t %s\t %s\" ]\n",
                    count, insn->address, insn->mnemonic, insn->op_str);
        else
            fprintf(output, "%s%8" PRIu64 "%s | 0x%"PRIx64":\t %s%s\t %s%s\n",
                    count ? "\033[1;32m" : "\033[1;30m",
                    count,
                    "\033[1;30m",
                    insn->address,
                    count ? "\033[1;32m" : "\033[1;30m",
                    insn->mnemonic, insn->op_str,
                    "\033[0;37m"
            );
    }
}

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    no_colors = getenv("COVERAGE_NO_COLORS") != NULL;
    coveralls_output = getenv("COVERAGE_COVERALLS") != NULL;
    // output coverage for each symbol
    g_hash_table_foreach(symbol_table, output_symbol_coverage, (gpointer)tpi);
    // clean everything
    g_hash_table_destroy(symbol_table);
    g_hash_table_destroy(address_table);
    cs_free(insn, 1);
    cs_close(&cs_handle);
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
    TPI_DECL_FUNC_1(tpi, after_exec_opc, void, i64);

    tpi->after_gen_opc  = after_gen_opc;
    tpi->cpus_stopped = cpus_stopped;

    if (cs_open(CS_ARCH, CS_MODE, &cs_handle) != CS_ERR_OK)
        abort();
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    output = tpi->output;
    insn = cs_malloc(cs_handle);

    symbol_table = g_hash_table_new_full(
        g_str_hash, g_str_equal, g_free, g_free);
    address_table = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL, g_free);
}


#endif /* CONFIG_CAPSTONE */
