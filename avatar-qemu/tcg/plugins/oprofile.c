/*
 * TCG plugin for QEMU: print an oprofile-like execution summary
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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>

#include "tcg-plugin.h"
#include "disas/disas.h"

#include <glib.h>


static bool ignore_unknown_symbols = true;

static GHashTable *sym_hash; /* symbol -> sym_hash_entry */

static uint64_t total_count = 0;

struct sym_hash_entry
{
  const char *symbol;
  const char *filename;
  uint64_t count;
  GHashTable *pc_hash; /* address -> pc_hash_entry */
};

struct pc_hash_entry
{
  uint64_t address;
  uint64_t count;
};


static void free_sym_hash_entry(gpointer data)
{
  struct sym_hash_entry *sym_hash_entry = (struct sym_hash_entry *)data;
  g_hash_table_destroy(sym_hash_entry->pc_hash);
  g_free(sym_hash_entry);
}


static gint compare_sym_hash_entries (gconstpointer a, gconstpointer b)
{
  return
    ((struct sym_hash_entry *)a)->count - ((struct sym_hash_entry *)b)->count;
}


static gint compare_pc_hash_entries (gconstpointer a, gconstpointer b)
{
  return
    ((struct pc_hash_entry *)a)->address - ((struct pc_hash_entry *)b)->address;
}


static void tb_helper_func(const TCGPluginInterface *tpi, TPIHelperInfo info,
			   uint64_t address, uint64_t data1, uint64_t data2,
               const TranslationBlock* tb)
{
  if (data1 != 0 && info.icount != 0)
    {
      uint32_t instruction_size = info.size / info.icount;
      uint64_t high_address = address + info.size;
      struct sym_hash_entry *sym_hash_entry =
	(struct sym_hash_entry *)(uintptr_t)data1;

      total_count += info.icount;
      sym_hash_entry->count += info.icount;
      /* wrong addresses on variable-length instruction set cpus,
	 unless -singlestep option is used  */
      do
	{
	  struct pc_hash_entry *pc_hash_entry;

	  pc_hash_entry =
	    g_hash_table_lookup(sym_hash_entry->pc_hash, &address);
	  if (pc_hash_entry == 0)
	    {
	      pc_hash_entry = g_new(struct pc_hash_entry, 1);
	      pc_hash_entry->address = address;
	      pc_hash_entry->count = 0;
	      g_hash_table_insert(sym_hash_entry->pc_hash,
				  g_memdup(&address, sizeof(address)),
				  pc_hash_entry);
	    }
	  pc_hash_entry->count += 1;
	  address += instruction_size;
	}
      while (address < high_address);
    }
}

static guint
int64_hash (gconstpointer v)
{
  return (guint) *(const gint64*) v;
}

static gboolean
int64_equal(gconstpointer v1,
	    gconstpointer v2)
{
  return *((const gint64*) v1) == *((const gint64*) v2);
}

static void tb_helper_data(const TCGPluginInterface *tpi, TPIHelperInfo info,
			   uint64_t address, uint64_t *data1, uint64_t *data2,
               const TranslationBlock* tb)
{
  struct sym_hash_entry *sym_hash_entry;
  const char *symbol, *filename;
  lookup_symbol2(address, &symbol, &filename);

  if (symbol[0] == '\0')
    {
      if (ignore_unknown_symbols)
	{
	  *data1 = 0;
	  return;
	}
      symbol = "/unknown";
    }
  if (filename[0] == '\0')
    {
      filename = "/unknown";
    }
  else
    {
      filename = basename((char*)filename);
    }

  sym_hash_entry = g_hash_table_lookup(sym_hash, symbol);
  if (sym_hash_entry == 0)
    {
      char *symbol_cp = g_strdup(symbol);
      char *filename_cp = g_strdup(filename);

      sym_hash_entry = g_new(struct sym_hash_entry, 1);
      sym_hash_entry->count = 0;
      sym_hash_entry->symbol = symbol_cp;
      sym_hash_entry->filename = filename_cp;
      /* Use local version of int64_hash/int64_equal for compatibility with glib < 2.22.  */
      sym_hash_entry->pc_hash =
	g_hash_table_new_full(int64_hash, int64_equal, g_free, g_free);
      g_hash_table_insert(sym_hash, symbol_cp, sym_hash_entry);
    }
  *data1 = (uintptr_t)sym_hash_entry;
}


static void cpus_stopped(const TCGPluginInterface *tpi)
{
#define addr2line(ADDR) "(no localization information)"
  GList *sym_list_elem, *sym_hash_entries =
    g_hash_table_get_values(sym_hash);

  fprintf(tpi->output, "%-16s %-9s %-7s %-30s %-30s %s\n",
	  "vma","samples", "%", "linenr_info", "image_name", "symbol_name");
  sym_hash_entries = /* sort by frequency */
    g_list_sort(sym_hash_entries, compare_sym_hash_entries);
  for (sym_list_elem = g_list_last(sym_hash_entries); sym_list_elem != 0;
       sym_list_elem = g_list_previous(sym_list_elem))
    {
      struct pc_hash_entry *first_pc_hash_entry;
      struct sym_hash_entry *sym_hash_entry =
	(struct sym_hash_entry *)g_list_nth_data(sym_list_elem, 0);
      GList *pc_list_elem, *pc_hash_entries =
	g_hash_table_get_values(sym_hash_entry->pc_hash);

      pc_hash_entries =
	g_list_sort(pc_hash_entries, compare_pc_hash_entries);
      first_pc_hash_entry =
	(struct pc_hash_entry *)g_list_nth_data(pc_hash_entries, 0);
      fprintf(tpi->output, "%016" PRIx64 " %-9" PRIu64 " %-7.4f %-30s %-30s %s\n",
	      first_pc_hash_entry->address, sym_hash_entry->count,
	      ((double)sym_hash_entry->count / total_count) * 100.0,
	      addr2line(first_pc_hash_entry->address),
	      sym_hash_entry->filename,
	      sym_hash_entry->symbol);
      for (pc_list_elem = g_list_first(pc_hash_entries); pc_list_elem != 0;
	   pc_list_elem = g_list_next(pc_list_elem))
	{
	  struct pc_hash_entry *pc_hash_entry =
	    (struct pc_hash_entry *)g_list_nth_data(pc_list_elem, 0);

	  fprintf(tpi->output,
		  "  %016" PRIx64 " %-9" PRIu64 " %-7.4f %s\n",
		  pc_hash_entry->address, pc_hash_entry->count,
		  ((double)pc_hash_entry->count / sym_hash_entry->count) * 100.0,
		  addr2line(pc_hash_entry->address)
		  );
	}
    }
  g_hash_table_destroy(sym_hash);
}


void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
    tpi->pre_tb_helper_code = tb_helper_func;
    tpi->pre_tb_helper_data = tb_helper_data;
    tpi->cpus_stopped = cpus_stopped;
    sym_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
				     g_free, free_sym_hash_entry);
}

