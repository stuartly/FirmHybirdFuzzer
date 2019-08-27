/*
 * TCG plugin for QEMU: simulate a IO memory mapped device (mainly
 *                      interesting to prototype things in user-mode).
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

/* You can test this plugin in user-mode with the following code:
 *
 * int main(void)
 * {
 * 	char *device = mmap(0xCAFE0000, 1024, PROT_READ, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
 * 	return printf("printf(%p): %s\n", device, device);
 * }
 */

#include <stdint.h>
#include <inttypes.h>

#include "tcg-op.h"
#include "tcg-plugin.h"

static const char *quote = "Real programmers can write assembly code in any language.  :-)\n\t-- Larry Wall";
#define BASE 0xCAFE0000

static uint64_t extend64(uint64_t val, int bits, int is_signed)
{
    uint64_t one_mask = ~(uint64_t)0;
    if (bits >= 64) return val;
    if (bits <= 0) return is_signed ? one_mask: 0;
    if (!is_signed || (val & (1 << (bits-1))) == 0) {
        val &= one_mask >> (64 - bits);
    } else {
        val |= one_mask << bits;
    }
    return val;
}

static uint64_t after_exec_opc(uint64_t value, uint64_t address, int32_t signed_size)
{
    int ld_size = signed_size < 0 ? -signed_size: signed_size;
    size_t max_index = strlen(quote);
    size_t index     = address - BASE;
    size_t size      = MIN(ld_size, max_index - index + 1);

    if (address < BASE || address > BASE + max_index)
        return value;

    memcpy(&value, &quote[index], size);

    extend64(value, ld_size * 8, signed_size < 0);

    return value;
}

static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    int size;
    int sign;
    switch (tpi_opcode->operator) {
    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        break;
    default:
        return;
    }

    TCGMemOp opc = get_memop(tpi_opcode->opargs[2]);
    size = 1 << (opc & MO_SIZE);
    sign = (opc & MO_SIGN) != 0 ? -1: 1;

    TCGTemp *args[3];
    TCGv_i64 tcgv_ret = tcg_temp_new_i64();
    TCGv_i32 tcgv_size = tcg_const_i32(size * sign);

    args[0] = arg_temp(tpi_opcode->opargs[0]); /* value loaded */
    args[1] = arg_temp(tpi_opcode->opargs[1]); /* address */
    args[2] = tcgv_i32_temp(tcgv_size); /* sign * size constant */

    /* get possibly modified value in tcgv_ret. */
    tcg_gen_callN(after_exec_opc, tcgv_i64_temp(tcgv_ret), 3, args);
    tcg_temp_free_i32(tcgv_size);

    /* overwrite destination register. */
    tcg_gen_mov_i64(temp_tcgv_i64(arg_temp(tpi_opcode->opargs[0])), tcgv_ret);
    tcg_temp_free_i64(tcgv_ret);

}


void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);

    TPI_DECL_FUNC_3(tpi, after_exec_opc, i64, i64, i64, i32);

    /* Sorry, for simplicity works on 64 bits hosts only. */
    assert(TCG_TARGET_REG_BITS == TARGET_LONG_BITS);
    assert(TCG_TARGET_REG_BITS == 64);

    tpi->after_gen_opc = after_gen_opc;
}
