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
#endif

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

#define MAX_PRINT_SIZE 128

static csh cs_handle;
static FILE *output;
static cs_insn *insn;

static void write_str(uint64_t str_intptr)
{
    char *str = (char *)(intptr_t)str_intptr;

    fwrite(str, sizeof(char), strlen(str), output);
}

static void gen_printf_insn(const TCGPluginInterface *tpi, cs_insn *insn)
{

    printf("Inst PC: 0x%"PRIx64":\t %s\t %s\t //\n",
                     insn->address,
                     insn->mnemonic,
                     insn->op_str);
}


static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    int decoded;
    const uint8_t *code = (const uint8_t *)(intptr_t)tpi_guest_ptr(tpi, tpi_opcode->pc);
    size_t size = 4096;
    uint64_t address = tpi_opcode->pc;

    if (tpi_opcode->operator != INDEX_op_insn_start) return;

    decoded = cs_disasm_iter(cs_handle,
                             &code, &size, &address, insn);
    if (decoded) {
        gen_printf_insn(tpi, insn);
    } else {
        printf("Inst PC: 0x%"PRIx64"\n", tpi_opcode->pc);
    }
}

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    cs_free(insn, 1);
    cs_close(&cs_handle);
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
    TPI_DECL_FUNC_1(tpi, write_str, void, i64);

    if (cs_open(CS_ARCH, (cs_mode) (CS_MODE_ARM + CS_MODE_THUMB + CS_MODE_MCLASS), &cs_handle) != CS_ERR_OK)
        abort();

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    insn = cs_malloc(cs_handle);

    tpi->after_gen_opc  = after_gen_opc;
    tpi->cpus_stopped  = cpus_stopped;
}

#endif /* CONFIG_CAPSTONE */
