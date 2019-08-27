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
#include <inttypes.h>
#include <unistd.h>

#include "tcg-plugin.h"

static uint64_t *icount_total;

static void pre_tb_helper_code(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t data1, uint64_t data2,
                               const TranslationBlock* tb)
{
    atomic_add(&icount_total[info.cpu_index], info.icount);
}

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    unsigned int i;
    for (i = 0; i < tpi->nb_cpus; i++) {
        fprintf(tpi->output,
                "%s (%d): number of executed instructions on CPU #%d = %" PRIu64 "\n",
                tcg_plugin_get_filename(), getpid(), i,
                icount_total[i]);
    }
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);

    tpi->pre_tb_helper_code = pre_tb_helper_code;
    tpi->cpus_stopped = cpus_stopped;

    icount_total = g_malloc0(tpi->nb_cpus * sizeof(uint64_t));
}
