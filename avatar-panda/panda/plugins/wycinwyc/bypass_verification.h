#ifndef BYPASS_VERIFICATION_H
#define BYPASS_VERIFICATION_H

#include "wycinwyc.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"


// plugin support
bool enable_bypass_verification(void* self, panda_cb pcb);
bool bypass_func_or_bb(CPUState *cpu, TranslationBlock *tb);


#endif
