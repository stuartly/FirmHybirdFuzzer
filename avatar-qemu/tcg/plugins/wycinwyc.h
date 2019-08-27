#ifndef WYCINWYC_H
#define WYCINWYC_H

#include "tcg-plugin.h"
#include <capstone/capstone.h>
#include "stl/vector.h"
#include "stl/map.h"

extern vector *mappings; // mappings.item.memory_range

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

// copy from panda/src/common.c, return -1 means error
// CPUState *env = tpi_current_cpu(tpi);
int qemu_virtual_memory_rw(CPUState *env, target_ulong addr,
                        uint8_t *buf, int len, int is_write);
#endif // ! WYCINWYC_H
