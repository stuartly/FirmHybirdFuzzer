#include "bypass_verification.h"
#ifdef TARGET_ARM


bool bypass_func_or_bb(CPUState *cpu, TranslationBlock *tb) {  
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;

    std::map<target_ulong, target_long>::iterator findfunc = bypass_func_addr_map_ret.find(tb->pc);
    std::map<target_ulong, target_long>::iterator findbb = bypass_bb_addr_map_addr.find(tb->pc);
    // hook net func
    if (tb->pc <= 0) {
        printf("this shouldnt happen\n");
        return false;
    }
    else if (findfunc != bypass_func_addr_map_ret.end()) {
        printf("bypass function......pc: 0x%08x\n", tb->pc);
        env->regs[0] = (target_ulong)findfunc->second;
        uint32_t ret_addr = (env->regs[14] & (~(uint32_t)0 << 1));
        env->regs[15] = ret_addr;
        return true;
    }
    else if (findbb != bypass_bb_addr_map_addr.end()) {
        printf("bypass basic block......pc: 0x%08x\n", tb->pc);
        env->regs[15] = (target_ulong)findbb->second;
        return true;
    }
    else {
        return false;
    }
}


bool enable_bypass_verification(void* self, panda_cb pcb) {
    printf("\nInit plugin bypass_verification!\n");

    pcb.before_block_exec_invalidate_opt = bypass_func_or_bb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

    return true;
}

#endif
