#ifndef DIV_TRACKING_H
#define DIV_TRACKING_H

#include "wycinwyc.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"


extern std::map<target_ulong, std::vector<cs_insn>> tb_insns_map;

bool enable_div_tracking(void *self, panda_cb pcb);

int before_insn_exec_cb(CPUState *cpu, target_ulong pc);


#endif