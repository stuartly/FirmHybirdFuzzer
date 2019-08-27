#ifndef INST_TRACKING_H
#define INST_TRACKING_H

#include "wycinwyc.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"


extern std::map<target_ulong, std::vector<cs_insn>> tb_insns_map;

bool enable_inst_tracking(void *self, panda_cb pcb);

int before_insn_exec(CPUState *cpu, target_ulong pc);
bool before_insn_translate(CPUState *cpu, target_ulong pc);


#endif