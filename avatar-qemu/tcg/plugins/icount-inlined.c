/*
 * TCG plugin for QEMU: count the number of executed instructions per
 *                      CPU.  This plugin is *not* thread-safe!
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

static TCGArg **icount_total_args;
static uint64_t *icount_total;

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    unsigned int i;
    for (i = 0; i < tpi->nb_cpus; i++) {
        fprintf(tpi->output,
                "%s (%d): number of executed instructions on CPU #%d = %" PRIu64 "\n",
                tcg_plugin_get_filename(), getpid(), i, icount_total[i]);
    }
}

/* This function generates code which is *not* thread-safe!  */
static void before_gen_tb(const TCGPluginInterface *tpi)
{
    TCGv_ptr icount_ptr;
    TCGv_i64 icount_tmp;
    TCGv_i32 tb_icount32;
    TCGv_i64 tb_icount64;

    /* icount_ptr = &icount */
    icount_ptr = tcg_const_ptr((tcg_target_long)&icount_total[tpi_current_cpu_index(tpi)]);

    /* icount_tmp = *icount_ptr */
    icount_tmp = tcg_temp_new_i64();
    tcg_gen_ld_i64(icount_tmp, icount_ptr, 0);

    /* tb_icount32 = fixup(tb->icount) */
    /* icount_args = &tb_icount32 */

    tb_icount32 = tcg_const_i32(0);
    icount_total_args[tpi_current_cpu_index(tpi)] = &tcg_last_op()->args[1];

    /* tb_icount64 = (int64_t)tb_icount32 */
    tb_icount64 = tcg_temp_new_i64();
    tcg_gen_extu_i32_i64(tb_icount64, tb_icount32);

    /* icount_tmp += tb_icount64 */
    tcg_gen_add_i64(icount_tmp, icount_tmp, tb_icount64);

    /* *icount_ptr = icount_tmp */
    tcg_gen_st_i64(icount_tmp, icount_ptr, 0);

    tcg_temp_free_i64(tb_icount64);
    tcg_temp_free_i32(tb_icount32);
    tcg_temp_free_i64(icount_tmp);
    tcg_temp_free_ptr(icount_ptr);
}

static void after_gen_tb(const TCGPluginInterface *tpi)
{
    /* Patch parameter value.  */
    *icount_total_args[tpi_current_cpu_index(tpi)] = tpi_tb_icount(tpi->tb);
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION(tpi);

    tpi->cpus_stopped  = cpus_stopped;
    tpi->before_gen_tb = before_gen_tb;
    tpi->after_gen_tb  = after_gen_tb;

    icount_total = g_malloc0(tpi->nb_cpus * sizeof(uint64_t));
    icount_total_args = g_malloc0(tpi->nb_cpus * sizeof(TCGArg *));

    {
        unsigned int i;
        for (i = 0; i < tpi->nb_cpus; ++i) {
            char name[] = "cpu_icount_X";
            unsigned int len = strlen(name);
            name[len - 1] = '0' + i;
            tpi_declare_param_uint(tpi, name, icount_total + i, 0,
                                   "number of instructions per cpu");
        }
    }
}
