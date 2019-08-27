#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcg-plugin.h"
#include "wycinwyc.h"

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

static target_ulong cs_pc = 0x0;
static csh cs_handle;
static cs_insn *insn;
static char *__divsi3_pc_str = NULL;


int get_value(CPUArchState *env, char op_str[], target_ulong *value)
{
    // r0, r1, r2, r3, r4, r5, r6, r7, r8,
    // r9-sb, r10-sl, r11-fp, r12-ip, r13-sp, r14-lr, r15-pc    
    int index;
    switch (op_str[0])
    {
    case 'r':
        index = atoi(&op_str[1]);
        assert(0 <= index && 15 >= index);
        *value = env->regs[index];
        break;
    case 's': 
        if(op_str[1] == 'b')
            *value = env->regs[9];
        else if(op_str[1] == 'l')
            *value = env->regs[10];
        else if(op_str[1] == 'p')
            *value = env->regs[13];
        else
            assert(0);
        break;
    case 'f': *value = env->regs[11]; break;
    case 'i': *value = env->regs[12]; break;
    case 'l': *value = env->regs[14]; break;
    case 'p': *value = env->regs[15]; break;
    case '#': *value = strtol(&op_str[1], NULL, 0); break;
    default: return -1;
    }
    return 0;
}

static inline int get_op_len(char *op_str)
{
    int i = 0;
    for(; op_str[i] != ',' && op_str[i] != '\0'; ++i)
        ;
    return i;
}

void __divsi3_cb(const TCGPluginInterface *tpi, cs_insn *insn)
{
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    target_ulong arg1;
    if(get_value(env, "r1", &arg1) != -1)
    {
        if(0U == arg1)
        {
            printf("[!] Divisor is zero at 0x%x!\n", insn->address);
        }
    }
}

void div_cb(const TCGPluginInterface *tpi, cs_insn *insn){
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    char *op2_str = NULL;
    char *ops = insn->op_str;
    int op_index = 0, i = 0;
    for(i = 0; ops[i] != '\0'; i++)
    {
        if(ops[i] == ',') ++op_index;
        if(2 == op_index)
        {
            int len = get_op_len(&ops[++i]);
            op2_str = (char *)malloc(len);
            strncpy(op2_str, &ops[++i], len);
            op2_str[len-1] = '\0';
            target_ulong op2_value;
            if(get_value(env, op2_str, &op2_value) != -1)
            {
                //printf("div op2_val %d at 0x%x!\n", op2_value, insn->address);
                if(0U == op2_value)
                {
                    printf("[!] Divisor is zero at 0x%x!\n", insn->address);
                }
            }
            else
            {
                printf("[-] Failed to get value of div op2 at 0x%x!\n", insn->address);
            }
            break;
        }
    }
    if(op2_str != NULL)
    {
        free(op2_str);
    }
}

void add_cb(const TCGPluginInterface *tpi, cs_insn *insn)
{
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    char *op0_str = NULL, *op1_str = NULL, *op2_str = NULL;
    target_ulong op0_value, op1_value, op2_value;
    char* ops = insn->op_str;
    int op_index = 0, i = 0;
    for(i = 0; ops[i] != '\0'; i++)
    {
        if(ops[i] == ',') ++op_index;
        if(0 == op_index && NULL == op0_str)
        {
            int len = get_op_len(&ops[i]) + 1;
            op0_str= (char *)malloc(len*sizeof(char));
            strncpy(op0_str, &ops[i], len);
            op0_str[len-1] = '\0';
            // printf("#%s#\n", op0_str);
            if(get_value(env, op0_str, &op0_value) != -1)
            {
                // printf("add op0_val %d at 0x%x!\n", op0_value, insn->address);
            }
            else
            {
                printf("[-] Failed to get value of add op0 at 0x%x!\n", insn->address);
                break;
            }
        }
        else if(1 == op_index && NULL == op1_str)
        {
            int len = get_op_len(&ops[++i]);
            op1_str= (char *)malloc(len*sizeof(char));
            strncpy(op1_str, &ops[++i], len);
            op1_str[len-1] = '\0';
            // printf("#%s#\n", op1_str);
            if(get_value(env, op1_str, &op1_value) != -1)
            {
                // printf("add op1_val %d at 0x%x!\n", op1_value, insn->address);
            }
            else
            {
                op_index = -1;
                printf("[-] Failed to get value of add op1 at 0x%x!\n", insn->address);
                break;
            }
        }
        else if(2 == op_index)
        {
            int len = get_op_len(&ops[++i]);
            op2_str = (char *)malloc(len*sizeof(char));
            strncpy(op2_str, &ops[++i], len);
            op2_str[len-1] = '\0';
            if(get_value(env, op2_str, &op2_value) != -1)
            {
                // printf("add op2_val %d at 0x%x!\n", op2_value, insn->address);
            }
            else
            {
                op_index = -1;
                printf("[-] Failed to get value of add op2 at 0x%x!\n", insn->address);
            }
            break;
        }
    }
    if(op0_str != NULL) free(op0_str);
    if(op1_str != NULL) free(op1_str);
    if(op2_str != NULL) free(op2_str);

    if(op_index == 2)
    {
        if(op1_value < 0 && op2_value < 0)
        {
            if(INT_MIN - op1_value > op2_value)
            {
                printf("[!] Int overflow at 0x%x!\n", insn->address);
            }
        }
        else if(op1_value > 0 && op2_value > 0)
        {
            if(INT_MAX - op1_value < op2_value)
            {
                printf("[!] Int overflow at 0x%x!\n", insn->address);
            }
        }
    }
    else if(op_index == 1)
    {
        if(op0_value < 0 && op1_value < 0)
        {
            if(INT_MIN - op0_value > op1_value)
            {
                printf("[!] Int overflow at 0x%x!\n", insn->address);
            }
        }
        else if(op0_value > 0 && op1_value > 0)
        {
            if(INT_MAX - op0_value < op1_value)
            {
                printf("[!] Int overflow at 0x%x!\n", insn->address);
            }
        }
    }
}

static void gen_printf_insn(const TCGPluginInterface *tpi, cs_insn *insn)
{
    printf("Inst PC2: 0x%x\t %s\t %s\t 0x%x%x\t//\n",
                     insn->address,
                     insn->mnemonic,
                     insn->op_str,
                     insn->bytes[0],
                     insn->bytes[1]);
}

static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *op)
{
    uint64_t pc = op->pc;
    if(cs_pc == pc)
        return;
    else
        cs_pc = pc;

    // printf("Inst PC1: 0x%x\n", cs_pc);
    int decoded;
    size_t size = 4;
    uint8_t *code = (uint8_t *)malloc(size);
    CPUState *env = tpi_current_cpu(tpi);
    int err = qemu_virtual_memory_rw(env, pc, code, size, 0);
    // printf("bin0x%02x%02x\n", *code, *(code+1));
    if (err == -1 ) printf("[-] Couldn't read TB memory!\n");
    if (op->operator != INDEX_op_insn_start) return;

    size_t count = cs_disasm(cs_handle, code, size, pc, 1, &insn);
    // decoded = cs_disasm_iter(cs_handle, &code, &size, &address, insn);
    if (count) 
    {
        // gen_printf_insn(tpi, insn);
        uint32_t insn_id = insn->id;
        TCGv_ptr t_tpi = tcg_const_ptr(tpi);
        TCGv_ptr t_insn = tcg_const_ptr(insn);
        if(insn_id == ARM_INS_SDIV || insn_id == ARM_INS_UDIV || insn_id == ARM_INS_VDIV)
        {
            // printf("gen_div\n");
            TCGTemp *args[] = {tcgv_ptr_temp(t_tpi), tcgv_ptr_temp(t_insn)};
            tcg_gen_callN(div_cb, TCG_CALL_DUMMY_ARG, sizeof(args) / sizeof(args[0]), args);
        }
        else if (insn_id == ARM_INS_ADD) 
        {
            TCGTemp *args[] = {tcgv_ptr_temp(t_tpi), tcgv_ptr_temp(t_insn)};
            tcg_gen_callN(add_cb, TCG_CALL_DUMMY_ARG, sizeof(args) / sizeof(args[0]), args);
        }
        else if (NULL != __divsi3_pc_str && strcmp(__divsi3_pc_str, insn->op_str) == 0)
        {
            TCGTemp *args[] = {tcgv_ptr_temp(t_tpi), tcgv_ptr_temp(t_insn)};
            tcg_gen_callN(__divsi3_cb, TCG_CALL_DUMMY_ARG, sizeof(args) / sizeof(args[0]), args);
        }
        tcg_temp_free_ptr(t_tpi);
        tcg_temp_free_ptr(t_insn);
    } 
    else
    {
        // printf("Inst PC3: 0x%x\n", pc);
    }

    return;
}

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    cs_free(insn, 1);
    cs_close(&cs_handle);
}

void tpi_init(TCGPluginInterface *tpi)
{

    TPI_INIT_VERSION(tpi);

    if (cs_open(CS_ARCH, (cs_mode) (CS_MODE_THUMB + CS_MODE_MCLASS), &cs_handle) != CS_ERR_OK)
        abort();

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    __divsi3_pc_str = getenv("__divsi3_pc");
    if(NULL != __divsi3_pc_str && 0 == strlen(__divsi3_pc_str))
    {
        __divsi3_pc_str  == NULL;
    }

    TPI_DECL_FUNC_2(tpi, div_cb, void, ptr, ptr);
    TPI_DECL_FUNC_2(tpi, add_cb, void, ptr, ptr);
    TPI_DECL_FUNC_2(tpi, __divsi3_cb, void, ptr, ptr);
    tpi->after_gen_opc = after_gen_opc;
    tpi->cpus_stopped  = cpus_stopped;
    
    printf("Init plugin div_tracking!\n");
}

#endif
