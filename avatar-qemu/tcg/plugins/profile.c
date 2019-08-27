/*
 * TCG plugin for QEMU: count the number of executed instructions per
 *                      function.
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
#include <pthread.h>

#include "tcg-plugin.h"
#include "disas/disas.h"

#include <glib.h>

static GHashTable *hash;

typedef struct {
    const char *symbol;
    const char *filename;
} HashKey;

typedef struct {
    uint64_t size;
    uint64_t icount;
} HashValue;

static void pre_tb_helper_code(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t data1, uint64_t data2,
                               const TranslationBlock* tb)
{
    HashValue *hash_value = (HashValue *)(uintptr_t)data1;
    hash_value->size   += info.size;
    hash_value->icount += info.icount;
}

static void pre_tb_helper_data(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t *data1, uint64_t *data2,
                               const TranslationBlock* tb)
{
    HashKey hash_key;
    HashValue *hash_value;

    lookup_symbol2(address, &hash_key.symbol, &hash_key.filename);

    if (hash_key.symbol[0] == '\0') {
        hash_key.symbol = "<unknown>";
        hash_key.filename = "<unknown>";
    }

    hash_value = g_hash_table_lookup(hash, &hash_key);
    if (!hash_value) {
        hash_value = g_new0(HashValue, 1);
        g_hash_table_insert(hash, g_memdup(&hash_key, sizeof(hash_key)), hash_value);
    }

    *data1 = (uintptr_t)hash_value;
}

/**********************************************************************
 * Pretty printing.
 */

static size_t symbol_length   = 0;
static size_t filename_length = 0;
static size_t nb_bytes_length = 0;
static size_t nb_instr_length = 0;
static char format[1024] = "";

static unsigned int ilog10(uint64_t value)
{
    unsigned int result = 0;
    do { result++; } while(value /= 10);
    return result;
}

static void compute_entry_length(const HashKey *hash_key, const HashValue *hash_value)
{
    symbol_length   = MAX(symbol_length, strlen(hash_key->symbol));
    filename_length = MAX(filename_length, strlen(hash_key->filename));
    nb_bytes_length = MAX(nb_bytes_length, ilog10(hash_value->size));
    nb_instr_length = MAX(nb_instr_length, ilog10(hash_value->icount));
}

static void print_entry(const HashKey *hash_key, const HashValue *hash_value, FILE *output)
{
    fprintf(output, format, hash_key->symbol, hash_key->filename, hash_value->size, hash_value->icount);
}

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    size_t line_length = 0;

    symbol_length   = strlen("SYMBOL");
    filename_length = strlen("FILENAME");
    nb_bytes_length = strlen("#BYTES");
    nb_instr_length = strlen("#INSTR");
    g_hash_table_foreach(hash, (GHFunc)compute_entry_length, NULL);

    snprintf(format, sizeof(format), "%%-%zus | %%-%zus | %%%zus | %%%zus\n",
             symbol_length, filename_length, nb_bytes_length, nb_instr_length);
    fprintf(tpi->output, format, "SYMBOL", "FILENAME", "#BYTES", "#INSTR");

    line_length = filename_length + 3 + symbol_length + 3 + nb_bytes_length + 3 + nb_instr_length;
    do { fprintf(tpi->output, "-"); } while (line_length--);
    fprintf(tpi->output, "\n");

    snprintf(format, sizeof(format), "%%-%zus | %%-%zus | %%%zu" PRIu64 " | %%%zu" PRIu64 "\n",
             symbol_length, filename_length, nb_bytes_length, nb_instr_length);

    fprintf(tpi->output, "%s (%d):\n", tcg_plugin_get_filename(), getpid());
    g_hash_table_foreach(hash, (GHFunc)print_entry, tpi->output);
}

/**********************************************************************
 * Hash helpers.
 */

static guint hash_func(gconstpointer a)
{
    const HashKey *key = a;
    return g_str_hash(key->symbol) + g_str_hash(key->filename);
}

static gboolean key_equal_func(gconstpointer a, gconstpointer b)
{
    const HashKey *key1 = a;
    const HashKey *key2 = b;
    return g_str_equal(key1->symbol, key2->symbol) + g_str_equal(key1->filename, key2->filename);
}

/**********************************************************************/

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);

    tpi->pre_tb_helper_code = pre_tb_helper_code;
    tpi->pre_tb_helper_data = pre_tb_helper_data;
    tpi->cpus_stopped = cpus_stopped;

    hash = g_hash_table_new_full(hash_func, key_equal_func, g_free, g_free);
}
