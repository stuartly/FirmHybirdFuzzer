#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include "tcg-plugin.h"
#include "wycinwyc.h"
#include "stl/vector.h"
#include "stl/map.h"
#include "stl/cJSON.h"


#ifdef CONFIG_CAPSTONE
#include <capstone/capstone.h>
/* Check compatibility with capstone 3.x. */
#if CS_API_MAJOR < 3
#error "stackobject plugin required capstone library >= 3.x. Please install from http://www.capstone-engine.org/."
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
            "# WARNING: stackobject plugin disabled.\n"
            "#          capstone library >= 3.x was not found when configuring QEMU.\n"
            "#          Install capstone from http://www.capstone-engine.org/\n"
            "#          and reconfigure/recompile QEMU.\n"
        );
#elif !defined(CS_ARCH)
    fprintf(tpi->output,
            "# WARNING: stackobject plugin disabled.\n"
            "           This plugin is not available for target " TARGET_NAME ".\n"
        );
#endif
}
#else

csh cs_handle_32;
csh cs_handle_64;

static target_ulong before_pc = 0x0;
static cs_insn last_insn;
static bool return_pending = false;

vector *callframesStack = NULL;   // a stack to shore call_frames
map *tb_insns_map = NULL;
map *call_cache = NULL;

static target_ulong prev_write_addr = 0;
static target_ulong prev_write_size = 0;
static target_ulong prev_write_frame = 0;

// load_json
vector *get_stack_obj(const char *filename, target_ulong env_pc)
{
	// read data from file
	FILE *fp = fopen(filename, "r");
	if (fp == NULL)
	{
		printf("file %s open failed.\n", filename);
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	int filesize = ftell(fp);
	// printf("filesize %d\n", filesize);
	fseek(fp, 0, SEEK_SET);
	char *filedata = (char *)malloc(filesize + 1);
	fread(filedata, sizeof(char), filesize+1, fp);
	// printf("%s\n", filedata);
	fclose(fp);

    cJSON *pJson = cJSON_Parse(filedata);
    char env_pc_str[13];
    sprintf(env_pc_str, "%d", env_pc);
    cJSON *func = cJSON_GetObjectItem(pJson, env_pc_str);
    vector *root = (vector *)malloc(sizeof(vector)), *cur_node = root;
    root->next = NULL;
    if (func != NULL)
    {
        cJSON *stack = cJSON_GetObjectItem(func, "stack_variables");
        cJSON *stackobj = NULL;
        cJSON_ArrayForEach(stackobj, stack)
        {
            vector *new_node = (vector *)malloc(sizeof(vector));

            stack_object_t so;
            so.offset = cJSON_GetObjectItem(stackobj, "dw_at_location_offset")->valueint;
            // todo: should copy?
            char *name = cJSON_GetObjectItem(stackobj, "name")->valuestring;
            int name_len = strlen(name) ? strlen(name) : 1;
            so.name = (char *)malloc(sizeof(char)*name_len); // Convenient unified free
            strcpy(so.name, name);
            so.size = cJSON_GetObjectItem(stackobj, "size")->valueint;
            vector_item vit;
            vit.so = so;
            new_node->item = vit;
            new_node->next = NULL;

            cur_node->next = new_node;
            cur_node = cur_node->next;
        }
    }
    cJSON_Delete(pJson);
	vector *ret = root->next;
	free(root);
    free(filedata);

	return ret;
}


static uint32_t memory_op_size(TCGMemOp memflags)
{
    switch (memflags & MO_SIZE)
    {
    case MO_8:
        return 1;
    case MO_16:
        return 2;
    case MO_32:
        return 4;
    case MO_64:
        return 8;
    }
    assert(0);
    return 0;
}


static void printf_insn(cs_insn *insn)
{
    printf("Inst: 0x%x\t %s\t %s\t \n",
                     insn->address,
                     insn->mnemonic,
                     insn->op_str);
}


static target_ulong find_frame_by_address(target_ulong addr)
{
    if (!GetVectorSize(callframesStack))
            return 0;

    vector *cur = callframesStack;
    while(cur != NULL)
    {
        callframe cf = cur->item.cf;
        if(addr > cf.sp)
        {
            return cf.sp;
        }
        cur = cur->next;

    }
    return 0;
}


void on_mem_write(CPUArchState *env, target_ulong pc, target_ulong addr, target_ulong size)
{
    target_ulong cur_frame = find_frame_by_address(addr);
    if (GetVectorSize(callframesStack) > 1 && cur_frame && prev_write_frame)
    {
        if (prev_write_addr + prev_write_size == addr)
        {
            if (cur_frame != prev_write_frame)
            {
                printf("[!] Detected stack-corrupting memory write at 0x%08x!\n", pc);
                printf(" |  Previous_memory_access_address: 0x%08x\n", prev_write_addr);
                printf(" |  Current_memory_access_address: 0x%08x\n", addr);
                printf(" |  Previous_write_stack_frame: 0x%08x\n", prev_write_frame);
                printf(" |  Current_write_stack_frame: 0x%08x\n", cur_frame);
                return;
            }
        }
        prev_write_addr = 0;
        prev_write_size = 0;
        prev_write_frame = 0;
    }
    prev_write_addr = addr;
    prev_write_size = size;
    prev_write_frame = cur_frame;
    return 0;
}


// refer to panda/plugins/callstack_instr.cpp
instr_type disas_block(CPUArchState* env, target_ulong pc, int size)
{
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = qemu_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
#if !defined(TARGET_X86_64)
    // not every block in i386 is necessary executing in the same processor mode
    // need to make capstone match current mode or may miss call statements
    if ((env->hflags & HF_CS32_MASK) == 0)
        cs_option(handle, CS_OPT_MODE, CS_MODE_16);
    else
        cs_option(handle, CS_OPT_MODE, CS_MODE_32);
#endif
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32;

    if (env->thumb)
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    else
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);

#elif defined(TARGET_PPC)
    csh handle = cs_handle_32;
#endif

    cs_insn *insn;
    cs_insn *end;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);

    if (count <= 0) goto done2;

    for (end = insn + count - 1; end >= insn; end--)
    {
        if (!cs_insn_group(handle, end, CS_GRP_INVALID))
        {
            break;
        }
    }
    if (end < insn) goto done;

    if (cs_insn_group(handle, end, CS_GRP_CALL))
        res = INSTR_CALL;
    else if (cs_insn_group(handle, end, CS_GRP_RET))
        res = INSTR_RET;
    else
        res = INSTR_UNKNOWN;

done:
    cs_free(insn, count);
done2:
    free(buf);
    return res;
}


static void after_gen_tb(const TCGPluginInterface *tpi)
{
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    CPUState *cpu = tpi_current_cpu(tpi);
    TranslationBlock *tb = tpi->tb;

    instr_type tb_type = disas_block(env, tb->pc, tb->size);
    key_map k;
    value_map v;
    k.call_cache_k = tb->pc;
    v.call_cache_v = tb_type;
    call_cache = SetValueInMap(k, v, call_cache);

    k.tb_insns_k = tb->pc;
    if (IsKeyInMap(k, tb_insns_map))
        return;

    uint8_t *tb_opcodes_buffer = (uint8_t *) malloc(tb->size);
    qemu_virtual_memory_rw(cpu, tb->pc, tb_opcodes_buffer, tb->size, 0);
    csh handle;
    cs_insn *insn;
    // wycinwyc-specific: thumb == cortex-m
    cs_mode mode = env->thumb ? (cs_mode) (CS_MODE_THUMB + CS_MODE_MCLASS) : CS_MODE_ARM;
    if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Unable to invoke capstone!\n");
        exit(-1);
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    size_t count = cs_disasm(handle, tb_opcodes_buffer, tb->size, tb->pc, 0, &insn);
    if (count <= 0)
    {
        fprintf(stderr, "Error during disassembling at " TARGET_FMT_lx, tb->pc);
        exit(-1);
    }

    vector *insn_vec = NULL;
    vector_item vi;
    size_t i = 0;
    for (i = 0; i < count; i++)
    {
        vi.csinsn = insn[i];
        // printf_insn(insn+i);
        insn_vec = PushBackVector(vi, insn_vec);
    }
    k.tb_insns_k = tb->pc;
    v.tb_insns_v = insn_vec;
    tb_insns_map = SetValueInMap(k, v, tb_insns_map);

    free(tb_opcodes_buffer);
    free(insn);
}


void on_call(const CPUArchState *env)
{
    // r0, r1, r2, r3, r4, r5, r6, r7, r8
    // r9-sb, r10-sl, r11-fp, r12-ip, r13-sp, r14-lr, r15-pc
    uint64_t fp = env->regs[11];
    uint64_t sp = env->regs[13];
    uint64_t lr = env->regs[14];
    uint64_t pc = env->regs[15];
    uint64_t size = fp - sp; // error, too large? should be pre_sp-sp!

    // create and store callframe info
    callframe cf;
    cf.fp = fp;
    cf.sp = sp;
    cf.lr = lr & (~(uint32_t)0 << 1);
    cf.pc = pc;
    cf.size = size;
    cf.before_pc = before_pc;

    vector_item callframe_item;
    callframe_item.cf = cf;
    callframesStack = PushBackVector(callframe_item, callframesStack);
    // PrintVector(callframesStack);
}


static void after_exec_tb(const TCGPluginInterface *tpi)
{
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    TranslationBlock *tb = tpi->tb;

    key_map k;
    k.call_cache_k = tb->pc;
    instr_type cur_tb_type = GetValueInMap(k, call_cache).call_cache_v;
    k.tb_insns_k = tb->pc;
    vector *cur_insn_vec = GetValueInMap(k, tb_insns_map).tb_insns_v;
    cs_insn last_insn = GetVectorEnd(cur_insn_vec)->item.csinsn;

    if (cur_tb_type == INSTR_CALL)
    {
        on_call(env);
    }

    uint64_t pc = env->regs[15];
    uint64_t sp = env->regs[13];

    if (return_pending)
    {
        // printf("Return at pc = 0x%x, sp = 0x%x\n", pc, sp);
        return_pending = false;

        if (before_pc == pc)
        {
            printf("caller pc == callee pc, this should not happen!\n");
            return;
        }

        // get caller
        vector *cf_vec = GetVectorEnd(callframesStack);
        if (cf_vec == NULL)
            printf("[!] Found return to 0x08%x without callee from 0x%08x\n"
                   " |  Previous Instruction: %s\t%s\n",
                    pc, last_insn.address, last_insn.mnemonic, last_insn.op_str);

        else if (pc != (cf_vec->item.cf.lr))
        {
            // check if the pc after return is equal to the callInst_pc + offset;
            uint64_t callee_return = cf_vec->item.cf.lr;
            printf("[!] Found return to 0x%08x with mismatching callee 0x%08x from 0x%08x\n"
                   " |  Previous Instruction: %s\t%s\n",
                    pc, callee_return, last_insn.address, last_insn.mnemonic, last_insn.op_str);

        }
        callframesStack = PopBackVector(callframesStack);
    }
}


static void before_exec_tb(const TCGPluginInterface *tpi)
{
    CPUArchState *env = tpi_current_cpu_arch(tpi);

    uint32_t pc = env->regs[15];
    TranslationBlock *tb = tpi->tb;

    key_map k;
    k.tb_insns_k = tb->pc;
    vector *cur_insn_vec = GetValueInMap(k, tb_insns_map).tb_insns_v;
    cs_insn insn = GetVectorEnd(cur_insn_vec)->item.csinsn;
    if (insn.id == ARM_INS_LDMDB || insn.id == ARM_INS_POP ||
       (insn.id == ARM_INS_MOV && insn.detail->arm.operands[0].reg == ARM_REG_PC)  ||
       (insn.id == ARM_INS_BX  && insn.detail->arm.operands[0].reg == ARM_REG_LR))
    {
        last_insn = insn;
        return_pending = true;
        before_pc = pc;
    }
}


static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *op)
{
    const TCGOpcode opc = op->opcode->opc;
    uint64_t pc = op->pc;

    // detect load/store
    switch (opc)
    {
    // load/store from guest memory
    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_st_i32:
        break;
    default:
        return;
    }

    const TCGMemOpIdx flags = op->opargs[2];
    const TCGMemOp memflags = get_memop(flags);
    uint32_t memory_size = memory_op_size(memflags);

    CPUArchState *env = tpi_current_cpu_arch(tpi);
    TCGv_ptr t_env = tcg_const_ptr(env);
    TCGv_i64 t_pc = tcg_const_i64(pc);
    TCGArg addr = op->opargs[1];
    TCGv_i32 t_size = tcg_const_i32(memory_size);

    TCGTemp *args[] = {tcgv_ptr_temp(t_env), tcgv_i64_temp(t_pc),
                       arg_temp(addr), tcgv_i32_temp(t_size)};

    tcg_gen_callN(on_mem_write, TCG_CALL_DUMMY_ARG,
                      sizeof(args) / sizeof(args[0]), args);

    tcg_temp_free_ptr(t_env);
    tcg_temp_free_i64(t_pc);
    tcg_temp_free_i32(t_size);
}


static void cpus_stopped(const TCGPluginInterface *tpi)
{
    // free callframesStack
    DestoryVector(callframesStack);
    // free tb_insns_map
    map *head = tb_insns_map;
    map *p = head;
    map *q = NULL;
    if (head != NULL)
    {
        while (p->next != NULL)
        {
            q = p->next;
            p->next = q->next;
            DestoryVector(q->v.tb_insns_v);
            free(q);
        }
        if (p->next == NULL)
        {
            free(p);
        }
    }
    // free call_cache
    DestoryMap(call_cache);
}


void tpi_init(TCGPluginInterface *tpi)
{
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
        return false;
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
        return false;
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#endif

    // Need details in capstone to have instruction groupings
    cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
#endif

    TPI_INIT_VERSION(tpi);
    TPI_DECL_FUNC_4(tpi, on_mem_write, void, ptr, i64, i64, i64);
    tpi->after_gen_opc  = after_gen_opc;
    tpi->cpus_stopped  = cpus_stopped;
    tpi->before_exec_tb = before_exec_tb;
    tpi->after_exec_tb  = after_exec_tb;
    tpi->after_gen_tb = after_gen_tb;
    
    printf("load stackobject_tracking plugin done!\n");
}

#endif
