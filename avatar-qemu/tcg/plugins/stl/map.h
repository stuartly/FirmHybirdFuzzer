#ifndef MAP_H
#define MAP_H

#include "tcg-plugin.h"
#include "vector.h"

typedef enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
}instr_type;

typedef union key_map {
    target_ulong allocated_obj_k;
    target_ulong stack_obj_k;
    target_ulong tb_insns_k;
    target_ulong call_cache_k;
} key_map;

typedef union value_map {
    target_ulong allocated_obj_v;    
    vector *stack_obj_v;
    vector *tb_insns_v;
    instr_type call_cache_v;
} value_map;

typedef struct map
{
    key_map k;
    value_map v;
    struct map *next;
} map;

void PrintMap(map *head);

int IsKeyEquals(const key_map k1, const key_map k2);

map *CreatePair(const key_map k, const value_map v);

value_map GetValueInMap(const key_map k, map *head);

value_map GetEndValueInMap(map *head);

int IsKeyInMap(const key_map k, map *head);

// todo: better to pass a function pointer, to replace IsKeyEquals()!
//       maybe IsKeyInMap() etc better to do this, too.
map *SetValueInMap(const key_map k, const value_map v, map *head);

// if k or v is a ptr(linked list),it is not correct to call this function to DestoryMap
map *DestoryMap(map *head);

#endif // !MAP_H
