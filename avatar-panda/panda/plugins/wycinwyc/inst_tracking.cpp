#include "inst_tracking.h"

#include <string>
#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif


bool before_insn_translate(CPUState *cpu, target_ulong pc){
    return true;
}

int before_insn_exec(CPUState *cpu, target_ulong pc){
    printf("executing inst pc: 0x%04x\n", pc);
    return 0;
}

bool enable_inst_tracking(void* self, panda_cb pcb){

    pcb.insn_translate=before_insn_translate;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec=before_insn_exec;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    return true;
}
