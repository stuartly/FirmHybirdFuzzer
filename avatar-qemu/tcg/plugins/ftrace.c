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

/*
 * ftrace - function trace plugin
 *
 * Usage:
 *   $ env TPI_OUTPUT=ftrace.yml qemu-arch -tcg-plugin ftrace cmd...
 *
 * Generates a functioon entry/return trace with current
 * function backtrace information at each entry/return.
 * Functions entry/return events for all threads are interleaved.
 * Per thread function trace can be obtained by parsing the trace
 * and filtering per thread identifier.
 * 
 * The trace is a YAML file for the list of call entry/return
 * events.
 *
 * Scope:
 * - linux-user: ok
 * - linux-user threaded: ok
 * - bsd-user: not compiled, not tested
 * - bsd-user threaded: not compiled, not tested
 * - system: disabled
 * - generic: no
 * - archs: x86_64/i386/arm/aarch64 ok, others disabled
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "tcg-plugin.h"
#include "disas/disas.h"

/* Only ported to those architectures. */
#if defined(CONFIG_USER_ONLY) && \
    (defined(TARGET_X86_64) || defined(TARGET_I386) ||  \
     defined(TARGET_ARM) || defined(TARGET_AARCH64))
#define FTRACE_IMPLEMENTED 1
#else
#define FTRACE_IMPLEMENTED 0
#endif

#if FTRACE_IMPLEMENTED == 0
void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
#ifndef CONFIG_USER_ONLY
    fprintf(tpi->output,
            "# WARNING: ftrace plugin disabled. Only supported for user mode.\n"
        );
#else
    fprintf(tpi->output,
            "# WARNING: ftrace plugin disabled. Unsupported achitecture.\n"
        );
#endif
}
#else /* FTRACE_IMPLEMENTED != 0*/

/*
 * This plugin is based on some ABI conventions for the
 * detection of function entries and returns.
 * In particular, a function call entry instance is identified
 * in each thread call stack by:
 * - the call jump address,
 * - the stack pointer of the caller before the call,
 * - the return address just after the call jump.
 * These informations are computed in an architecture specific
 * way through the CPUArchState interface.
 */
#if defined(TARGET_X86_64)
static uint64_t get_callee_return_address(const TCGPluginInterface *tpi)
{
    /* The return address for a function on x86_64
       is on the top of stack on function entry.
       Note that we need a guest load.
    */
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    uint64_t top_of_stack;
    uint64_t return_address;
    top_of_stack = cpu_env->regs[R_ESP];
    return_address = tpi_guest_load64(tpi, top_of_stack);
    return return_address;
}

static uint64_t get_stack_pointer(const TCGPluginInterface *tpi)
{
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    return cpu_env->regs[R_ESP];
}

static uint64_t get_caller_stack_pointer(const TCGPluginInterface *tpi)
{
    /* On x86_64, the caller stack pointer is the
     * stack pointer on entry + sizeof(uint64_t) as
     * the call pushes the return address on the stack at the
     * call point.
     */
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    return cpu_env->regs[R_ESP] + sizeof(uint64_t);
}

#elif defined(TARGET_I386)
static uint64_t get_callee_return_address(const TCGPluginInterface *tpi)
{
    /* The return address for a function on i386
       is on the top of stack on function entry.
    */
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    uint64_t top_of_stack;
    uint64_t return_address;
    top_of_stack = cpu_env->regs[R_ESP];
    return_address = tpi_guest_load32(tpi, top_of_stack);
    return return_address;
}

static uint64_t get_stack_pointer(const TCGPluginInterface *tpi)
{
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    return cpu_env->regs[R_ESP];
}

static uint64_t get_caller_stack_pointer(const TCGPluginInterface *tpi)
{
    /* On i386, the caller stack pointer is the
     * stack pointer on entry + sizeof(uint32_t) as
     * the call pushes the return address on the stack at the
     * call point.
     */
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    return cpu_env->regs[R_ESP] + sizeof(uint32_t);
}

#elif defined(TARGET_ARM) || defined(TARGET_AARCH64)
static uint64_t get_callee_return_address(const TCGPluginInterface *tpi)
{
    /* The return address for a function on ARM is in 32b reg r14
       or 64b xreg 30.
       Clear low bit which is used for legacy 13/32 support.
    */
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    return cpu_env->aarch64 ? cpu_env->xregs[30]:
        (cpu_env->regs[14] & (~(uint64_t)0 << 1));
}

static uint64_t get_stack_pointer(const TCGPluginInterface *tpi)
{
    /* The stack pointer is on ARM is in 32b reg r13
       or 64b xreg 31. */
    const CPUArchState *cpu_env = tpi_current_cpu_arch(tpi);
    return cpu_env->aarch64 ? cpu_env->xregs[31]: cpu_env->regs[13];
}

static uint64_t get_caller_stack_pointer(const TCGPluginInterface *tpi)
{
    /* On ARM archs, the stack pointer is not changed during
       a call. */
    return get_stack_pointer(tpi);
}

#else
#error "Plugin not supported for this guest architecture "
#endif


/*
 * A function entry in the function call stack
 * is identified by the triplet: (function address,
 * caller stack pointer, call return address).
 * There may be multiple instances of such a triplet
 * in a call stack, and a return point
 * can be identified by searching bacward for the
 * first match for the pair (stack_pointer, return_address)..
 */
typedef struct {
    const char *sym_name;
    const char *file_name;
    uint64_t sym_address;
    uint64_t callee_return_address;
    uint64_t caller_stack_pointer;
    uint64_t id;
    uint32_t depth;
} entry_frame_t;

static void entry_frame_dump(const entry_frame_t *frame, int indent, FILE *out)
{
    fprintf(out, "%*s{ id: %"PRIu64", depth: %"PRIu32", sym_name: \"%s\", file_name: \"%s\", sym_addr: 0x%"PRIx64", stack_ptr: 0x%"PRIx64", return_addr: 0x%"PRIx64" }\n",
            indent, " ",
            frame->id,
            frame->depth,
            frame->sym_name, frame->file_name,
            frame->sym_address, frame->caller_stack_pointer, frame->callee_return_address);
}

typedef struct {
    int size;
    int num;
    entry_frame_t *elts;
    uint64_t frame_num;
    uint64_t future_return;
} call_stack_t;

static entry_frame_t *call_stack_push(call_stack_t *stack, const entry_frame_t *frame)
{
    entry_frame_t *pushed;
    if (stack->num + 1 > stack->size) {
        stack->elts = (entry_frame_t *)realloc(stack->elts, (stack->size + 256) * sizeof(entry_frame_t));
        stack->size += 256;
    }
    pushed = &stack->elts[stack->num];
    *pushed = *frame;
    pushed->id = stack->frame_num++;
    pushed->depth = stack->num++;
    return pushed;
}

static entry_frame_t *call_stack_find_and_unpile(call_stack_t *stack, const entry_frame_t *frame)
{
    int i;
    for (i = stack->num - 1; i >= 0; i--) {
        if (frame->callee_return_address == stack->elts[i].callee_return_address &&
            frame->caller_stack_pointer == stack->elts[i].caller_stack_pointer) {
            stack->num = i;
            return &stack->elts[i];
        }
    }
    return NULL;
}

static void call_stack_dump(const call_stack_t *stack, int indent, FILE *out)
{
    int i;
    for (i = 0; i < stack->num; i++) {
        fprintf(out, "%*s- ", indent, " ");
        entry_frame_dump(&stack->elts[i], 0, out);
    }
}

/*
 * Thread local state.
 */
typedef struct  {
    call_stack_t stack; /* The current thread call stack. */
} locals_t;
static __thread locals_t locals;

/*
 * We consider that an execution of the instruction at the
 * very start of a symbol is a function entry.
 * Actually some elements of the call stack may thus not
 * be ABI conformant callable functions.
 */
static void potential_call(const TCGPluginInterface *tpi, uint64_t sym_addr, const char *sym_str, const char *file_str)
{
    entry_frame_t frame;
    int is_entry = 0;

    frame.sym_name = sym_str;
    frame.file_name = file_str;
    frame.sym_address = sym_addr;
    frame.caller_stack_pointer = get_caller_stack_pointer(tpi);
    frame.callee_return_address = get_callee_return_address(tpi);

    if (locals.stack.future_return == frame.callee_return_address)
        is_entry = 1;

    if (is_entry) {
        entry_frame_t *pushed = call_stack_push(&locals.stack, &frame);
        {
            /* Atomic output of this thread event. */
            tpi_exec_lock(tpi);
            fprintf(tpi_output(tpi), "- call_entry: { tid: %"PRIu32", id: %"PRIu64", depth: %d, sym_name: \"%s\", file_name: \"%s\" }\n",
                    tpi_thread_tid(tpi), pushed->id, pushed->depth, sym_str, file_str);
            fprintf(tpi_output(tpi), "  frames:\n");
            call_stack_dump(&locals.stack, 4, tpi_output(tpi));
            fflush(tpi_output(tpi));
            tpi_exec_unlock(tpi);
        }
    }
}

static void potential_future_return(const TCGPluginInterface *tpi, uint64_t future_return)
{
    (void)tpi;
    locals.stack.future_return = future_return;
}

static void potential_return(const TCGPluginInterface *tpi, uint64_t address, uint64_t sym_addr)
{
    entry_frame_t *found;
    entry_frame_t frame;

    frame.sym_name = NULL;
    frame.sym_address = 0;
    frame.caller_stack_pointer = get_stack_pointer(tpi);
    frame.callee_return_address = address;

    found = call_stack_find_and_unpile(&locals.stack, &frame);
    
    if (found != NULL) {
        /* Atomic output of this thread event. */
        tpi_exec_lock(tpi);
        fprintf(tpi_output(tpi), "- call_return: { tid: %"PRIu32", id: %"PRIu64", depth: %d, sym_name: \"%s\", file_name: \"%s\" }\n",
                tpi_thread_tid(tpi), found->id, found->depth, found->sym_name, found->file_name);
        fprintf(tpi_output(tpi), "  frame:\n");
        call_stack_dump(&locals.stack, 4, tpi_output(tpi));
        fflush(tpi_output(tpi));
        tpi_exec_unlock(tpi);
    }
}

static void pre_tb_helper_code(const TCGPluginInterface *tpi, TPIHelperInfo info,
			   uint64_t address, uint64_t data1, uint64_t data2,
               const TranslationBlock* tb)
{
    const char *symbol = (const char *)(uintptr_t)data1;
    const char *filename = (const char *)(uintptr_t)data2;
    uint64_t tb_size, tb_address;
    uint64_t potential_return_address;

    tb_address = tpi_tb_address(tb);
    tb_size = tpi_tb_size(tb);
    potential_return_address = tb_address + tb_size;

    /* Any TB start address is a potential point of return. */
    potential_return(tpi, tb_address, 0);

    /* Any TB start address is a potential point of entry. */
    potential_call(tpi, tb_address, symbol, filename);

    /* The address following the current TB may be a point of return
       if this TB does a call. */
    potential_future_return(tpi, potential_return_address);

}

static void pre_tb_helper_data(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t *data1, uint64_t *data2,
                               const TranslationBlock* tb)
{
    const char *symbol = NULL;
    const char *filename = NULL;

    lookup_symbol2(address, &symbol, &filename);

    *data1 = (uintptr_t)symbol;
    *data2 = (uintptr_t)filename;
}


void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION(tpi);

    tpi->pre_tb_helper_code = pre_tb_helper_code;
    tpi->pre_tb_helper_data = pre_tb_helper_data;
}

#endif /* FTRACE_IMPLEMENTED != 0 */
