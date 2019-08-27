#include "div_tracking.h"




#include <string>
#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#ifdef TARGET_ARM

csh cs_handle_32;
csh cs_handle_64;

bool before_insn_translate_cb(CPUState *cpu, target_ulong pc){

    csh handle;
    cs_mode mode;
    size_t size = 4;
    unsigned char *buf = (unsigned char *) malloc(size);
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    int err = panda_virtual_memory_rw(cpu, pc, buf, size, 0);
    if (err == -1) fprintf(stderr, "Couldn't read TB memory!\n");
    bool ret = false;

    mode = env->thumb ? (cs_mode) (CS_MODE_THUMB + CS_MODE_MCLASS) : CS_MODE_ARM;

    if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK){
        fprintf(stderr, "Unable to invoke capstone!\n");
        goto done;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn;
    size_t count = cs_disasm(handle, buf, size, pc, 1, &insn);

    //printf("count inst: %x %12x %x %x %x\n", pc, *buf, sizeof(*buf), count, size);

    if (count <= 0) {
        //printf("cs_disasm return 0!\n");
        goto done;
    }
    //printf("insn_tracking %x %d %x %s %s\n", pc, insn->id, insn->address, insn->mnemonic, insn->op_str);
    //return true;

    uint32_t insn_id = insn->id;
    if(insn_id == ARM_INS_SDIV || insn_id == ARM_INS_UDIV || insn_id == ARM_INS_VDIV){
        ret = true;
        //printf("div_tracking true %x %x %s %s\n", pc, insn->address, insn->mnemonic, insn->op_str);
    }else if ( insn_id == ARM_INS_ADD) {
            // insn_id == ARM_INS_ADD     ||
            // insn_id == ARM_INS_QADD    || insn_id == ARM_INS_QADD16   || insn_id == ARM_INS_QADD8   ||
            // insn_id == ARM_INS_QDADD   ||
            // insn_id == ARM_INS_SADD16  || insn_id == ARM_INS_SADD8    ||
            // insn_id == ARM_INS_SHADD16 || insn_id == ARM_INS_SHADD8   ||
            // insn_id == ARM_INS_UADD16  || insn_id == ARM_INS_UADD8    ||
            // insn_id == ARM_INS_UHADD16 || insn_id == ARM_INS_UHADD8   ||
            // insn_id == ARM_INS_UQADD16 || insn_id == ARM_INS_UQADD8   ||
            // insn_id == ARM_INS_VADD    || insn_id == ARM_INS_VADDHN   || insn_id == ARM_INS_VADDL   || insn_id == ARM_INS_VADDW    ||
            // insn_id == ARM_INS_VHADD   ||
            // insn_id == ARM_INS_VPADDL  || insn_id == ARM_INS_VPADD    ||
            // insn_id == ARM_INS_VQADD   ||
            // insn_id == ARM_INS_VRADDHN ||
            // insn_id == ARM_INS_VRHADD  ||
            // insn_id == ARM_INS_ADDW
        ret = true;
        //printf("add_tracking false %x %x %s %s\n", pc, insn->address, insn->mnemonic, insn->op_str);
    }else if (insn_id == ARM_INS_MUL){
            // insn_id == ARM_INS_MUL      ||
            // insn_id == ARM_INS_SMMUL    || insn_id == ARM_INS_SMMULR    ||
            // insn_id == ARM_INS_SMULBB   || insn_id == ARM_INS_SMULBT    ||
            // insn_id == ARM_INS_SMULL    ||
            // insn_id == ARM_INS_SMULTB   || insn_id == ARM_INS_SMULTT    ||
            // insn_id == ARM_INS_SMULWB   || insn_id == ARM_INS_SMULWB    ||
            // insn_id == ARM_INS_UMULL    ||
            // insn_id == ARM_INS_VMUL     || insn_id == ARM_INS_VMULL     ||
            // insn_id == ARM_INS_VNMUL    ||
            // insn_id == ARM_INS_VQDMULH  || insn_id == ARM_INS_VQDMULL   ||
            // insn_id == ARM_INS_VQRDMULH 
        ret = true;
        //printf("mul_tracking false %x %x %s %s\n", pc, insn->address, insn->mnemonic, insn->op_str);
    }

    cs_free(insn, count);
done:
    //printf("return false");
    free(buf);
    return ret;
}

int add_ops_is_reg(CPUArchState *env, cs_insn *insn){
    std::string op=insn->op_str;
    int r0=op.find('r');
    if(r0==std::string::npos)return 0;
    int c0=op.find(',');
    int r1=op.find('r',c0);
    if(r1==std::string::npos)return 0;
    int c1=op.find(',',r1);
    int r2=op.find('r',c1);
    if(r2==std::string::npos)return 0;
    int i0=atoi(op.substr(r0+1, c0-r0-1).c_str());
    int i1=atoi(op.substr(r1+1, c1-r1-1).c_str());
    int i2=atoi(op.substr(r2+1).c_str());
    int32_t op0 = env->regs[i0];
    int32_t op1 = env->regs[i1];
    int32_t op2 = env->regs[i2];
    //printf("add_tracking exec %x r%d, r%d, r%d %d %d %d %d %d\n", insn->address, i0, i1, i2, op0, op1, op2, INT_MAX, INT_MIN);
    if(op1<0 && op2<0){
        if(INT_MIN-op1>op2){
            printf("[!] Int overflow at 0x%x!\n", insn->address);
        }
    }else if(op1>0 && op2 >0){
        if(INT_MAX-op1<op2){
            printf("[!] Int overflow at 0x%x!\n", insn->address);
        }
    }
    return 0;
}

int add_handle(CPUArchState *env, cs_insn *insn){
    uint32_t insn_id = insn->id;
    if(insn_id == ARM_INS_ADD){
        //adds ri, rj, rk
        //printf("add_tracking %d %x %s %s\n", insn->id, insn->address, insn->mnemonic, insn->op_str);
        std::string mne=insn->mnemonic;
        if(mne=="adds"){
            add_ops_is_reg(env, insn);
        }else if(mne=="adds.w"){
            std::string op=insn->op_str;
            //ads.w sl, sl, sb // r10, r10, r9
            if(op=="sl, sl, sb"){
//                for(int i=0;i<=15;i++){
//                    printf("reg%d:\t%d\n",i,env->regs[i]);
//                }
                int32_t op1 = env->regs[10];
                int32_t op2 = env->regs[9];
                if(op1<0 && op2<0){
                    if(INT_MIN-op1>op2){
                        printf("[!] Int overflow at 0x%x!\n", insn->address);
                    }
                }else if(op1>0 && op2 >0){
                    if(INT_MAX-op1<op2){
                        printf("[!] Int overflow at 0x%x!\n", insn->address);
                    }
                }
            }else{
                add_ops_is_reg(env, insn);
            }
        }
    }
    return 0;
}

int mul_handle(CPUArchState *env, cs_insn *insn){
    return 0;
}

int div_handle(CPUArchState *env, cs_insn *insn){
    std::string op=insn->op_str;
    int r0=op.find('r');
    int c0=op.find(',');
    int r1=op.find('r',c0);
    int c1=op.find(',',r1);
    int r2=op.find('r',c1);
    int i0=atoi(op.substr(r0+1, c0-r0-1).c_str());
    int i1=atoi(op.substr(r1+1, c1-r1-1).c_str());
    int i2=atoi(op.substr(r2+1).c_str());
    target_ulong op0 = env->regs[i0];
    target_ulong op1 = env->regs[i1];
    target_ulong op2 = env->regs[i2];
    printf("div_tracking exec %x r%d, r%d, r%d %u %u %u %u %u\n", insn->address, i0, i1, i2, op0, op1, op2, 0, 0U);
    if(op2==0U){
        fprintf(stderr, "Divisor is zero at 0x%x!\n", insn->address);
        printf("Divisor is zero at 0x%x!\n", insn->address);
    }
    return 0;
}

int before_insn_exec_cb(CPUState *cpu, target_ulong pc){
    //temp 
//    csh handle;
//    cs_mode mode;
//    size_t size = 4;
//    unsigned char *buf = (unsigned char *) malloc(size);
//    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
//    printf("insn exec before %x %x %x\n", pc, env->regs[14],env->regs[15]);
//    return 0;
    //temp 

     csh handle;
     cs_mode mode;
     size_t size = 4;
     unsigned char *buf = (unsigned char *) malloc(size);
     CPUArchState *env = (CPUArchState *) cpu->env_ptr;
     int err = panda_virtual_memory_rw(cpu, pc, buf, size, 0);
     if (err == -1) fprintf(stderr, "Couldn't read TB memory!\n");

     mode = env->thumb ? (cs_mode) (CS_MODE_THUMB + CS_MODE_MCLASS) : CS_MODE_ARM;

     if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK){
         fprintf(stderr, "Unable to invoke capstone!\n");
         goto done;
     }
     cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

     cs_insn *insn;
     size_t count = cs_disasm(handle, buf, size, pc, 1, &insn);
     uint32_t insn_id = insn->id;
     if(insn_id == ARM_INS_SDIV || insn_id == ARM_INS_UDIV || insn_id == ARM_INS_VDIV){
         div_handle(env, insn);
     }else if ( insn_id == ARM_INS_ADD) {
         add_handle(env, insn);
     }else if (insn_id == ARM_INS_MUL){
         mul_handle(env, insn);
     }
    
     cs_free(insn, count);
 done:
     free(buf);
     return 0;
}

bool enable_div_tracking(void* self, panda_cb pcb){

    pcb.insn_translate=before_insn_translate_cb;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec=before_insn_exec_cb;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    return true;
}

#endif
