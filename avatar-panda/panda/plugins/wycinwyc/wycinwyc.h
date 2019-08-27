#ifndef WYCINWYC_H
#define WYCINWYC_H

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "cpu.h"
#include "qemu-common.h"

#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <vector>
#include <queue>
#include <cstring>
#include <algorithm>
#include <cstdint>
#include <unistd.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
//wycinwyc specific imports
#include "segment_tracking.h"
#include "callstack_tracking.h"
#include "callframe_tracking.h"
#include "printf_tracking.h"
#include "heapobject_tracking.h"
#include "stackobject_tracking.h"
#include "hook_network.h"
#include "div_tracking.h"
#include "inst_tracking.h"
#include "bypass_verification.h"

extern "C"{
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qdict.h"
}

#ifdef TARGET_ARM

#define QDICT_ASSERT_KEY_TYPE(_dict, _key, _type) \
    g_assert(qdict_haskey(_dict, _key) && qobject_type(qdict_get(_dict, _key)) == _type)


struct memory_range {
    int address;
    int size;
    char perms;
    bool file_backed;
};

extern std::vector<memory_range> mappings;
extern std::map<target_ulong, std::vector<cs_insn>> tb_insns_map;

//format specifier function-addresses for printf-tracking
extern target_ulong printf_addr;
extern target_ulong fprintf_addr;
extern target_ulong dprintf_addr;
extern target_ulong sprintf_addr;
extern target_ulong snprintf_addr;

//allocation/deallocation for heapobject-tracking
extern target_ulong malloc_addr;
extern target_ulong realloc_addr;
extern target_ulong free_addr;
extern target_ulong calloc_addr;
extern target_ulong malloc_r_addr;
extern target_ulong realloc_r_addr;
extern target_ulong free_r_addr;

// network function-address for hook_network_tracking
extern target_ulong net_fun_addr;
extern const char* seed_path;
extern const char* gvfile_path;
extern uint32_t buf_reg_index;
extern uint32_t len_reg_index;
extern std::map<target_ulong, target_long> bypass_func_addr_map_ret;
extern std::map<target_ulong, target_long> bypass_bb_addr_map_addr;
// hook_network call .so
extern void *QemuInterface_so_handle;
extern void *ccallpy_so_handle;

extern "C"{
bool init_plugin(void *);
void uninit_plugin(void *);
}


QDict * load_json(const char * filename);
#endif
#endif
