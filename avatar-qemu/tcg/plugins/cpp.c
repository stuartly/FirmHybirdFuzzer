/* Support for C++ Plugin Interface */

#include "tcg-plugin.h"

#ifdef CONFIG_TCG_PLUGIN_CPP
#include "cpp/plugin_instrumentation_api.h"

#ifdef CONFIG_USER_ONLY
/* defined in linux-user/qemu.h */
extern bool get_mapped_file(uint64_t addr, const char** name,
                            uint64_t* base_addr);
#else
static bool get_mapped_file(uint64_t addr, const char** name,
                            uint64_t* base_addr)
{
    return false;
}
#endif


/* used to retrieve tb information before and after its generation */
static __thread translation_block** current_block_ptr;
static TCGPluginInterface* plugin_tpi;

/* code architecture dependent */
#if defined(TARGET_X86_64) || defined(TARGET_I386)
/* on i386/x86_64, return address in on the top of stack after a call is done */
static uint64_t get_callee_return_address(void)
{
    const CPUArchState* cpu_env = tpi_current_cpu_arch(plugin_tpi);
    uint64_t stack_ptr = cpu_env->regs[R_ESP];
#if defined(TARGET_X86_64)
    return tpi_guest_load64(plugin_tpi, stack_ptr);
#elif defined(TARGET_I386)
    return tpi_guest_load32(plugin_tpi, stack_ptr);
#endif
}

#if defined(TARGET_X86_64)
static enum architecture current_arch = ARCHITECTURE_X86_64;
#elif defined(TARGET_I386)
static enum architecture current_arch = ARCHITECTURE_I386;
#endif

#elif defined(TARGET_ARM) || defined(TARGET_AARCH64)
static uint64_t get_callee_return_address(void)
{
    /* The return address for a function on ARM is in 32b reg r14
       or 64b xreg 30.
       Clear low bit which is used for legacy 13/32 support.
       */
    const CPUArchState* cpu_env = tpi_current_cpu_arch(plugin_tpi);
    return cpu_env->aarch64 ? cpu_env->xregs[30]
                            : (cpu_env->regs[14] & (~(uint64_t)0 << 1));
}

#if defined(TARGET_AARCH64)
static enum architecture current_arch = ARCHITECTURE_AARCH64;
#elif defined(TARGET_ARM)
static enum architecture current_arch = ARCHITECTURE_ARM;
#endif

#else
#error "some functions are not implemented for current architecture"
#endif

static enum architecture get_guest_architecture(void)
{
    return current_arch;
}

static void on_block_exec(translation_block** b_ptr)
{
    /* it seems there is a bug with before_gen_tb.
     * The first instrumented block (despite before_gen_tb is called once) calls
     * twice this callback (with two different blocks reported).
     * Thus, just ignore first time we come through here */
    static bool first_time = true;
    if (first_time) {
        first_time = false;
        return;
    }

    event_block_enter(*b_ptr, get_callee_return_address());
}

static void on_load(translation_block** b_ptr, uint64_t pc, uint64_t addr,
                    uint32_t size)
{
    event_memory_access(*b_ptr, pc, addr, size, true);
}

static void on_store(translation_block** b_ptr, uint64_t pc, uint64_t addr,
                     uint32_t size)
{
    event_memory_access(*b_ptr, pc, addr, size, false);
}

// returns size (in bytes) of memory affected by operation
static uint32_t memory_op_size(TCGMemOp memflags)
{
    switch (memflags & MO_SIZE) {
    case MO_8:
        return 1;
    case MO_16:
        return 2;
    case MO_32:
        return 4;
    case MO_64:
        return 8;
    }
    assert(false);
    return 0;
}

static void after_gen_opc(const TCGPluginInterface* tpi, const TPIOpCode* op)
{
    if (!current_block_ptr)
        return;

    const TCGOpcode opc = op->opcode->opc;
    uint64_t pc = op->pc;

    bool is_load = false;

    // detect load/store
    switch (opc) {
    // load/store from guest memory
    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        is_load = true;
        break;
    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_st_i32:
        is_load = false;
        break;
    default:
        return;
    }

    const TCGMemOpIdx flags = op->opargs[2];
    const TCGMemOp memflags = get_memop(flags);
    uint32_t memory_size = memory_op_size(memflags);

    TCGv_ptr t_block = tcg_const_ptr(current_block_ptr);
    TCGv_i64 t_pc = tcg_const_i64(pc);
    TCGArg addr = op->opargs[1];
    TCGv_i32 t_size = tcg_const_i32(memory_size);

    TCGTemp *args[] = {tcgv_ptr_temp(t_block), tcgv_i64_temp(t_pc),
                       arg_temp(addr), tcgv_i32_temp(t_size)};

    if (is_load) {
        tcg_gen_callN(on_load, TCG_CALL_DUMMY_ARG,
                      sizeof(args) / sizeof(args[0]), args);
    } else {
        tcg_gen_callN(on_store, TCG_CALL_DUMMY_ARG,
                      sizeof(args) / sizeof(args[0]), args);
    }

    tcg_temp_free_ptr(t_block);
    tcg_temp_free_i64(t_pc);
    tcg_temp_free_i32(t_size);
}

static void before_gen_tb(const TCGPluginInterface* tpi)
{
    current_block_ptr = malloc(sizeof(translation_block*));

    TCGv_ptr t_block = tcg_const_ptr(current_block_ptr);

    TCGTemp *args[] = {tcgv_ptr_temp(t_block)};
    tcg_gen_callN(on_block_exec, TCG_CALL_DUMMY_ARG, 1, args);

    tcg_temp_free_ptr(t_block);
}

static void after_gen_tb(const TCGPluginInterface* tpi)
{
    if (!current_block_ptr)
        return;

    /* tb size is only available after tb generation */
    const TranslationBlock* tb = tpi->tb;
    uint64_t pc = tb->pc;
    const uint8_t* code = (const uint8_t*)tpi_guest_ptr(tpi, pc);

    const char* file = NULL;
    uint64_t load_address = 0;

    get_mapped_file(pc, &file, &load_address);

    translation_block* block =
        get_translation_block(pc, code, tb->size, file, load_address);
    /* patch current_block ptr */
    *current_block_ptr = block;
    current_block_ptr = NULL;
}

static void cpus_stopped(const TCGPluginInterface* tpi)
{
    event_cpus_stopped();

    //plugin_close();
}

void tpi_init(TCGPluginInterface* tpi)
{
    TPI_INIT_VERSION(tpi);
    TPI_DECL_FUNC_1(tpi, on_block_exec, void, ptr);
    TPI_DECL_FUNC_3(tpi, on_load, void, ptr, i64, i32);
    TPI_DECL_FUNC_3(tpi, on_store, void, ptr, i64, i32);

    tpi->before_gen_tb = before_gen_tb;
    tpi->after_gen_tb = after_gen_tb;
    tpi->after_gen_opc = after_gen_opc;
    tpi->cpus_stopped = cpus_stopped;
    plugin_tpi = tpi;

    plugin_init(tpi->output, get_guest_architecture());
}

#else
void tpi_init(TCGPluginInterface* tpi)
{
    fprintf(stderr, "cpp plugin support is not activated\n");
    exit(EXIT_FAILURE);
}

#endif /* CONFIG_TCG_PLUGIN_CPP */
