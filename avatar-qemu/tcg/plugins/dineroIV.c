/*
 * TCG plugin for QEMU: wrapper for Dinero IV (a cache simulator)
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
#include <math.h>

#include "tcg-plugin.h"

#define D4ADDR uint64_t
#include "d4-7/d4.h"
#include "d4-7/cmdd4.h"
#include "d4-7/cmdargs.h"

static FILE *output;
static d4cache *instr_cache, *data_cache;
static d4cache **caches_list;
static int caches_num;

static uint64_t instr_total;
static uint64_t load_total;
static uint64_t store_total;
static uint64_t cycles_total;

static uint32_t output_flags;
#define DINEROIV_DEFAULT_OUTPUTS "default"
#define OUTPUT_HELP      (1U<<0)
#define OUTPUT_COPYRIGHT (1U<<1)
#define OUTPUT_CYCLES    (1U<<2)
#define OUTPUT_STATS     (1U<<3)
#define OUTPUT_TRACE     (1U<<4)
#define OUTPUT_DINERO    (1U<<5)
#define OUTPUT_YAML      (1U<<6)
#define OUTPUTS_LEGACY_1 (OUTPUT_COPYRIGHT|OUTPUT_TRACE)
#define OUTPUTS_LEGACY_2 (OUTPUT_STATS|OUTPUT_CYCLES)
#define OUTPUTS_DEFAULT  (OUTPUT_STATS|OUTPUT_CYCLES|OUTPUT_YAML)

#define DINEROIV_DEFAULT_LATENCIES "0,2,40"
#define DINEROIV_DEFAULT_CMDLINE "-l1-isize 16k -l1-dsize 8192 -l1-ibsize 32 -l1-dbsize 16"
static int *caches_latencies;
static int latencies_num;

#define TYPE_IFETCH 0
#define TYPE_DREAD  1
#define TYPE_DWRITE 2
#define TYPE_NUM    3

typedef union {
    uint64_t data;
    struct {
        uint16_t size;
        uint16_t cpu_index;
        uint8_t type;
    };
} access_info_t;

static inline size_t type2index(char type) {
    switch (type) {
    case 'i': return TYPE_IFETCH;
    case 'r': return TYPE_DREAD;
    case 'w': return TYPE_DWRITE;
    }
    assert(0);
}

static inline const char *index2type(size_t index) {
    switch (index) {
    case TYPE_IFETCH: return "inst fetch";
    case TYPE_DREAD:  return "data fetch";
    case TYPE_DWRITE: return "data write";
    }
    assert(0);
}

static inline int index2dinero(size_t index) {
    switch (index) {
    case TYPE_IFETCH: return D4XINSTRN;
    case TYPE_DREAD: return D4XREAD;
    case TYPE_DWRITE: return D4XWRITE;
    }
    assert(0);
}

static void after_exec_opc(uint64_t info_data, uint64_t address, uint64_t pc)
{
    access_info_t info = { .data = info_data };

    if (output_flags & (OUTPUT_CYCLES|OUTPUT_STATS|OUTPUT_DINERO)) {

        d4memref memref;

        switch (info.type) {
        case 'i':
            instr_total += 1;
            memref.address    = pc;
            memref.accesstype = D4XINSTRN;
            memref.size       = (unsigned short) info.size;
            d4ref(instr_cache, memref);
            break;

        case 'r':
            load_total++;
            memref.address    = address;
            memref.accesstype = D4XREAD;
            memref.size       = (unsigned short) info.size;
            d4ref(data_cache, memref);
            break;

        case 'w':
            store_total++;
            memref.address    = address;
            memref.accesstype = D4XWRITE;
            memref.size       = (unsigned short) info.size;
            d4ref(data_cache, memref);
            break;

        default:
            assert(0);
        }
    }

    if (output_flags & OUTPUT_TRACE) {
        if (info.type == 'i') address = pc;
        fprintf(output, "%c 0x%016" PRIx64 " 0x%08" PRIx32 " (0x%016" PRIx64 ") CPU #%" PRIu32 " 0x%016" PRIx64 "\n",
                info.type, address, info.size, (uint64_t)0, info.cpu_index, pc);
    }
}

static void gen_helper(const TCGPluginInterface *tpi, TCGArg *opargs, int type, uint16_t size, uint64_t pc, int cpu_index);

static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    uint64_t pc;
    uint16_t size;
    int type;
    int cpu_index;

#define MEMACCESS(type_, size_) do {                       \
        type = type_;                                      \
        size = size_;                                      \
        cpu_index = tpi_opcode->cpu_index;                 \
        pc = tpi_opcode->pc;                               \
    } while (0);

    switch (tpi_opcode->operator) {
    case INDEX_op_insn_start:
#if defined(TARGET_SH4)
        MEMACCESS('i', 2);
#elif defined(TARGET_ARM)
        MEMACCESS('i', ARM_TBFLAG_THUMB(tpi->tb->flags) ? 2 : 4);
#else
        MEMACCESS('i', 4); /* Assume 4 bytes, even for variable length encoding. */
#endif
        break;

    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        MEMACCESS('r', 1 << (get_memop(tpi_opcode->opargs[2]) & MO_SIZE));
        break;

    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st_i64:
        MEMACCESS('w', 1 << (get_memop(tpi_opcode->opargs[2]) & MO_SIZE));
        break;

    default:
        return;
    }

    gen_helper(tpi, tpi_opcode->opargs, type, size, pc, cpu_index);
}

static void gen_helper(const TCGPluginInterface *tpi, TCGArg *opargs, int type, uint16_t size, uint64_t pc, int cpu_index)
{
    access_info_t info = { .type = type, .size = size, .cpu_index = cpu_index };
    TCGTemp *args[3];

    TCGv_i64 tcgv_info = tcg_const_i64(info.data);
    TCGv_i64 tcgv_pc   = tcg_const_i64(pc);

    args[0] = tcgv_i64_temp(tcgv_info);
    if (info.type != 'i') {
        args[1] = arg_temp(opargs[1]);
    } else {
        args[1] = tcgv_i64_temp(tcgv_pc);
    }
    args[2] = tcgv_i64_temp(tcgv_pc);

    tcg_gen_callN(after_exec_opc, TCG_CALL_DUMMY_ARG, 3, args);

    tcg_temp_free_i64(tcgv_pc);
    tcg_temp_free_i64(tcgv_info);
}

extern void dostats (void);
extern void doargs (int, char **);

static char *bigint_to_string(uint64_t bigint)
{
    /* Will print with comma separators as in 1,234,567. */
    uint64_t order_of_magnitude = bigint == 0 ? 1 :
        (uint64_t)pow(10, ((int)floor(log10(bigint)) / 3) * 3);
    uint64_t n = bigint;
    /* 1e20-1 > 2^64 > 1e19, hence 20 chars max for a uint64_t in base 10. */
    static char buffer[20+20/3+1]; /* Including commas and ending null byte. */
    char *ptr = buffer;
    size_t size = sizeof(buffer);

    while(order_of_magnitude > 0) {
        int c;
        if (n == bigint)
            c = snprintf(ptr, size, "%"PRIu64, n / order_of_magnitude) ;
        else
            c = snprintf(ptr, size, ",%03"PRIu64, n / order_of_magnitude) ;
        ptr += c;
        size -= c;
        n %= order_of_magnitude;
        order_of_magnitude /= 1000;
    }
    return buffer;
}

static void setup_caches_list(d4cache *instr_cache, d4cache *data_cache)
{
    d4cache *cache_ptr;

    caches_num = 0;
    caches_list = NULL;

    /* Fill caches list, instr caches first. */
    for (cache_ptr = instr_cache;
         cache_ptr != NULL;
         cache_ptr = cache_ptr->downstream, caches_num++) {
        d4cache *cache_ptr_uni;
        for (cache_ptr_uni = data_cache;
             cache_ptr_uni != NULL && cache_ptr_uni != cache_ptr;
             cache_ptr_uni = cache_ptr_uni->downstream)
            ;
        if (cache_ptr_uni == cache_ptr) {
            /* Found first unified level, stop there. */
            break;
        }
        caches_list = g_realloc(caches_list, (caches_num + 1) * sizeof(d4cache *));
        caches_list[caches_num] = cache_ptr;
    }
    for (cache_ptr = data_cache;
         cache_ptr != NULL;
         cache_ptr = cache_ptr->downstream, caches_num++) {
        caches_list = g_realloc(caches_list, (caches_num + 1) * sizeof(d4cache *));
        caches_list[caches_num] = cache_ptr;
    }
}

static bool get_cache_misses(const TCGPluginInterface *tpi, const char *name,
                             uint64_t *value)
{
    if (strcmp(name, "cache_misses") != 0)
        return false;

    *value = 0;

    {
        int type_idx;
        int cache_idx;
        for (type_idx = 0; type_idx < TYPE_NUM; type_idx++) {
            for (cache_idx = 0; cache_idx < caches_num; cache_idx++) {
                double misses =
                    caches_list[cache_idx]->miss[index2dinero(type_idx)];
                *value += misses;
            }
        }
    }

    return true;
}

static void dineroiv_sumup(FILE *output)
{
    int cache_idx;
    int type_idx;

    cycles_total = instr_total;

    /* Compute and dump stats per access type. */
    if (output_flags & OUTPUT_STATS) {
        fprintf(output, "\n");
        fprintf(output, "%s (%d): cache summary:\n",
                tcg_plugin_get_filename(), getpid());
    }
    for (type_idx = 0; type_idx < TYPE_NUM; type_idx++) {
        for (cache_idx = 0; cache_idx < caches_num; cache_idx++) {
            double fetches = caches_list[cache_idx]->fetch[index2dinero(type_idx)];
            double misses = caches_list[cache_idx]->miss[index2dinero(type_idx)];
            if (fetches > 0) {
                if (output_flags & OUTPUT_STATS) {
                    const char *type = index2type(type_idx);
                    const char *name = caches_list[cache_idx]->name;
                    fprintf(output, "%8s%12s in %9s: %26s", "", type, name,
                            bigint_to_string((uint64_t)fetches));
                    fprintf(output, "%8smisses: %26s", "",
                            bigint_to_string((uint64_t)misses));
                    fprintf(output, "%8smiss ratio: %10.6f %%", "",
                            trunc(misses/fetches * 100.0e6)/1.0e6);
                    fprintf(output, "\n");
                }
                /* Treat only data/inst reads for cycles estimate.
                   Assume that data stores are bypassed. */
                if (cache_idx < latencies_num) {
                    if (type_idx == TYPE_DREAD || type_idx == TYPE_IFETCH)
                        cycles_total += (uint64_t)fetches *
                            caches_latencies[cache_idx];
                }
            }
        }
    }

    if (output_flags & OUTPUT_STATS) {
        fprintf(output, "\n");
        fprintf(output, "%s (%d): instructions summary:\n",
                tcg_plugin_get_filename(), getpid());
        fprintf(output, "%8sinstrs: %26s\n", "",
                bigint_to_string(instr_total));
        fprintf(output, "%8s loads: %26s\n", "",
                bigint_to_string(load_total));
        fprintf(output, "%8sstores: %26s\n", "",
                bigint_to_string(store_total));
    }
}

static void dineroiv_sumup_yaml(FILE *output)
{
    int cache_idx;
    int type_idx;

    cycles_total = instr_total;

    /* Compute and dump stats per access type. */
    if (output_flags & OUTPUT_STATS) {
        fprintf(output, "\n");
        fprintf(output, "mem_accesses:\n");
    }
    for (cache_idx = 0; cache_idx < caches_num; cache_idx++) {
        const char *name = caches_list[cache_idx]->name;
        fprintf(output, "  - id: \"%s\"\n", name);
        for (type_idx = 0; type_idx < TYPE_NUM; type_idx++) {
            double fetches = caches_list[cache_idx]->fetch[index2dinero(type_idx)];
            double misses = caches_list[cache_idx]->miss[index2dinero(type_idx)];
            if (output_flags & OUTPUT_STATS) {
                const char *type = index2type(type_idx);
                fprintf(output, "    \"%s\": %"PRIu64"\n", type, (uint64_t)fetches);
                fprintf(output, "    \"%s missed\": %"PRIu64"\n", type, (uint64_t)misses);
                if (fetches > 0) {
                    fprintf(output, "    \"%s miss ratio\": %.10f\n", type,
                            misses/fetches);
                    fprintf(output, "    \"%s miss %%\": %.8f%%\n", type,
                            trunc(misses/fetches * 100.0e8)/1.0e8);
                } else {
                    fprintf(output, "    \"%s miss ratio\": %.10f\n", type, 0.0);
                    fprintf(output, "    \"%s miss %%\": %.8f%%\n", type, 0.0);
                }
                /* Treat only data/inst reads for cycles estimate.
                   Assume that data stores are bypassed. */
                if (cache_idx < latencies_num) {
                    if (type_idx == TYPE_DREAD || type_idx == TYPE_IFETCH)
                        cycles_total += (uint64_t)fetches *
                            caches_latencies[cache_idx];
                }
            }
        }
    }

    if (output_flags & OUTPUT_STATS) {
        fprintf(output, "\n");
        fprintf(output, "instructions_summary:\n");
        fprintf(output, "  count: %"PRIu64"\n", instr_total);
        fprintf(output, "  loads: %"PRIu64"\n", load_total);
        fprintf(output, "  stores: %"PRIu64"\n", store_total);
    }
}


static void cpus_stopped(const TCGPluginInterface *tpi)
{

    if (output_flags & (OUTPUT_CYCLES|OUTPUT_STATS|OUTPUT_DINERO)) {
        d4memref memref;
        /* Flush the data cache.  */
        memref.accesstype = D4XCOPYB;
        memref.address = 0;
        memref.size = 0;
        d4ref(data_cache, memref);
    }

    if (output_flags & (OUTPUT_CYCLES|OUTPUT_STATS)) {
        if (output_flags & (OUTPUT_YAML))
            dineroiv_sumup_yaml(tpi->output);
        else
            dineroiv_sumup(tpi->output);
    }

    if (output_flags & OUTPUT_DINERO) {
        FILE *old_stdout = stdout;
        stdout = tpi->output;
        dostats();
        stdout = old_stdout;
    }

    if (output_flags & OUTPUT_CYCLES) {
        if (output_flags & (OUTPUT_YAML)) {
            fprintf(tpi->output, "\n");
            fprintf(tpi->output, "estimated_cpi: %.4f\n", (double)cycles_total / instr_total);
            fprintf(tpi->output, "\n");
            fprintf(tpi->output, "estimated_cycles: %" PRIu64 "\n", cycles_total);
        } else {
            fprintf(tpi->output,
                    "%s (%d): number of estimated cycles = %" PRIu64 "\n",
                    tcg_plugin_get_filename(), getpid(), cycles_total);
        }
    }
}

static void parse_latencies(const char *latencies)
{
    const char *ptr = latencies;

    caches_latencies = NULL;
    latencies_num = 0;
    while (*ptr != '\0') {
        char *endptr;
        int latency = strtol(ptr, &endptr, 10);
        if (latency < 0 || (latency == 0 && endptr == ptr)) {
            fprintf(output, "# WARNING: %d latency invalid for cache idx %d, "
                    "while parsing DINERO_LATENCIES: %s\n",
                    latency, latencies_num, latencies);
            latency = 0;
        }
        caches_latencies = g_realloc(caches_latencies,
                                     (latencies_num + 1) * sizeof(*caches_latencies));
        caches_latencies[latencies_num] = latency;
        while(*ptr != '\0' && *ptr != ',')
            ptr++;
        if (*ptr == ',')
            ptr++;
        latencies_num += 1;
    }
}

static void parse_output_flags(const char *outputs)
{
    const char *ptr = outputs;
    int i;
    struct {
        const char *str;
        uint32_t flags;
    } matches[] = {
        { "help", OUTPUT_HELP },
        { "copyright", OUTPUT_COPYRIGHT },
        { "cycles", OUTPUT_CYCLES },
        { "stats", OUTPUT_STATS },
        { "trace", OUTPUT_TRACE },
        { "dinero", OUTPUT_DINERO },
        { "yaml", OUTPUT_YAML },
        { "default", OUTPUTS_DEFAULT },
        { "legacy-1", OUTPUTS_LEGACY_1 },
        { "legacy-2", OUTPUTS_LEGACY_2 }
    };

    output_flags = 0;
    while (*ptr != '\0') {
        for (i = 0; i < sizeof(matches)/sizeof(*matches); i++) {
            int len = strlen(matches[i].str);
            if (strncmp(ptr, matches[i].str, len) == 0 &&
                (ptr[len] == '\0' || ptr[len] == ',')) {
                output_flags |= matches[i].flags;
                ptr += len;
            }
        }
        while(*ptr != '\0' && *ptr != ',') ptr++;
        if (*ptr == ',') ptr++;
    }
}

void tpi_init(TCGPluginInterface *tpi)
{
    int i, argc;
    char **argv;
    char *cmdline;
    const char *latencies;
    const char *output_flags_str;

    TPI_INIT_VERSION(tpi);
    TPI_DECL_FUNC_3(tpi, after_exec_opc, void, i64, i64, i64);

    /* Sorry, for simplicity works on 64 bits hosts only. */
    assert(TCG_TARGET_REG_BITS == TARGET_LONG_BITS);
    assert(TCG_TARGET_REG_BITS == 64);

    assert(sizeof(access_info_t) == sizeof(uint64_t));

    output = tpi->output;

    tpi->after_gen_opc = after_gen_opc;
    tpi->cpus_stopped  = cpus_stopped;

    output_flags_str = getenv("DINEROIV_OUTPUTS");
    if (output_flags_str == NULL) output_flags_str = DINEROIV_DEFAULT_OUTPUTS;

    /* Parse output flags. */
    parse_output_flags(output_flags_str);

    if (output_flags & OUTPUT_CYCLES) {
        latencies = getenv("DINEROIV_LATENCIES");
        if (latencies == NULL) {
            latencies = DINEROIV_DEFAULT_LATENCIES;
            fprintf(output, "# WARNING: using default latencies "
                    "for cache hierarchy: %s\n", latencies);
            fprintf(output, "# INFO: use the DINEROIV_LATENCIES environment variable "
                    "to specify the cache hierarchy latencies\n");
        }
        /* Parse mem hierarchy latencies values. */
        parse_latencies(latencies);
    }

    if (output_flags & (OUTPUT_CYCLES|OUTPUT_STATS|OUTPUT_DINERO)) {
        cmdline = getenv("DINEROIV_CMDLINE");
        if (cmdline == NULL) {
            cmdline = g_strdup(DINEROIV_DEFAULT_CMDLINE);
            fprintf(output, "# WARNING: using default DineroIV cache hierarchy "
                    "command-line: %s\n", cmdline);
            fprintf(output, "# INFO: use the DINEROIV_CMDLINE environment variable "
                    "to specify the cache hierarchy command-line\n");
        }

        /* Create a valid argv[] for Dineroiv.  */
        argv = g_malloc0(2 * sizeof(char *));
        argv[0] = g_strdup("tcg-plugin-dineroIV");
        argv[1] = cmdline;
        argc = 2;

        for (i = 0; cmdline[i] != '\0'; i++) {
            if (cmdline[i] == ' ') {
                cmdline[i] = '\0';
                argv = g_realloc(argv, (argc + 1) * sizeof(char *));
                argv[argc++] = cmdline + i + 1;
            }
        }

        doargs(argc, argv);
        verify_options();
        initialize_caches(&instr_cache, &data_cache);

        if (data_cache == NULL) data_cache = instr_cache;

        setup_caches_list(instr_cache, data_cache);

        if (output_flags & OUTPUT_CYCLES) {
            if (latencies_num < caches_num) {
                fprintf(output, "# WARNING: provided latencies (%s) list does not match "
                        "the actual number of caches (%d)\n", latencies, caches_num);
            }
        }
    }

    if (output_flags & OUTPUT_HELP) {
        fprintf(output, "# WARNING: help no yet implemented, sorry\n");
    }

    if (output_flags & OUTPUT_COPYRIGHT) {
        fprintf(output, "---Dinero IV cache simulator, version %s\n", D4VERSION);
        fprintf(output, "---Written by Jan Edler and Mark D. Hill\n");
        fprintf(output, "---Copyright (C) 1997 NEC Research Institute, Inc. and Mark D. Hill.\n");
        fprintf(output, "---All rights reserved.\n");
        fprintf(output, "---Copyright (C) 1985, 1989 Mark D. Hill.  All rights reserved.\n");
        fprintf(output, "---See -copyright option for details\n");
    }

    static uint64_t cache_misses_fake;
    tpi_declare_param_uint(tpi, "cache_misses", &cache_misses_fake, 0,
                           "dynamically return cache_misses");
    /* register special cache misses parameter */
    tpi->get_param_uint = &get_cache_misses;
}
