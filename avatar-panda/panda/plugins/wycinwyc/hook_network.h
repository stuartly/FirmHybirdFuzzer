#ifndef HOOK_NETWORK_H
#define HOOK_NETWORK_H

#include "wycinwyc.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"


void hexdump(uint8_t *buf, uint32_t len);

// plugin support
bool enable_hook_network(void* self, panda_cb pcb);
bool replace_net_fun(CPUState *cpu, TranslationBlock *tb);


#endif