#include <stdio.h>
#include "tcg-plugin.h"
#include "wycinwyc.h"
#include "stl/vector.h"
#include "stl/map.h"

// can be reused
static uint32_t memory_op_size(TCGMemOp memflags)
{
    switch (memflags & MO_SIZE)
    {
    case MO_8:
        return 1;
    case MO_16:
        return 2;
    case MO_32:
        return 4;
    case MO_64:
        return 8;
    }
    assert(0);
    return 0;
}

static vector *freed_objects;  // freed_objects.item.freed_obj
static map *allocated_objects; // k:allocated_objects.k.allocated_obj_k
                               // v:allocated_objects.v.allocated_obj_v

static target_ulong malloc_ret  = 0;
static target_ulong malloc_size = 0;

static target_ulong realloc_ret = 0;
static target_ulong realloc_obj = 0;
static target_ulong realloc_size= 0;

static target_ulong free_ret    = 0;
static target_ulong free_obj    = 0;

static target_ulong calloc_ret  = 0;
static target_ulong calloc_size = 0;


void phys_mem_write_heapobject_cb(CPUArchState *env, target_ulong tpc, target_ulong addr, target_ulong size)
{
    target_ulong lr = env->regs[14];
    target_ulong pc = env->regs[15];
    // return if we are currently in an allocation routine
    if (malloc_ret || free_ret || calloc_ret || realloc_ret)
        return ;

    vector *fobj = freed_objects;
    for (; fobj != NULL; fobj = fobj->next)
    {
        if (fobj->item.freed_obj == addr)
        {
            printf("[!] Detected use-after-free of object at 0x%x (pc=0x%08x)\n", addr, pc);
            break;
        }
    }

    map * map_it = allocated_objects;
    for (; map_it != NULL; map_it = map_it->next)
    {
        if ( addr == map_it->k.allocated_obj_k - 4 || addr == map_it->k.allocated_obj_k + map_it->v.allocated_obj_v + 4 )
        {
            printf("[!] Heapcorruption at 0x%x detected (pc = 0x%08x - lr = 0x%08x)\n", addr, pc, lr);
        }    
    }
}

vector *EraseItemInVector(const vector_item data, vector *head)
{
    vector *cur = head, *prev = head, *newH = head;
    int isFind = 0;
    while(cur != NULL)
    {
        if(cur->item.freed_obj == data.freed_obj)
        {
            isFind = 1;
            break;
        }
        else
        {
            prev = cur;
            cur = cur->next;
        }
    }
    if(isFind)
    {
        if(cur == head)
        {
            prev = cur->next;
            free(cur);
            newH = prev;
        }
        else
        {
            prev->next = cur->next;
            free(cur);
        }
    }
    return newH;
}

int update_free_list(target_ulong addr, target_ulong size){
    vector *pos = freed_objects;

    int num_deleted = 0;

    while ( pos != NULL)
    {
        if (pos->item.freed_obj >= addr && pos->item.freed_obj < addr + size)
        {
            freed_objects = EraseItemInVector(pos->item, freed_objects);      
            num_deleted++;
        }
        else
        {
            pos = pos->next;
        }
        
    }
    return num_deleted;
}

map *EraseByKeyMap(key_map km, map* head)
{
    map *cur = head, *prev = head, *newH = head;
    int isFind = 0;
    while(cur != NULL)
    {
        if(cur->k.allocated_obj_k == km.allocated_obj_k)
        {
            isFind = 1;
            break;
        }
        else
        {
            prev = cur;
            cur = cur->next;
        }
    }
    if(isFind)
    {
        if(cur == head)
        {
            prev = cur->next;
            free(cur);
            newH = prev;
        }
        else
        {
            prev->next = cur->next;
            free(cur);
        }
    }
    return newH;
}


void after_block_exec_heapobject_cb(const TCGPluginInterface *tpi)
{
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    target_ulong pc = env->regs[15];
    target_ulong r0 = env->regs[0];

    key_map k;
    value_map v;
    if (pc == malloc_ret){
        k.allocated_obj_k = r0;
        v.allocated_obj_v = malloc_size;
        allocated_objects = SetValueInMap(k, v, allocated_objects);
        update_free_list(r0, malloc_size);

        malloc_ret = 0;
        malloc_size = 0;
    }

    if (pc == calloc_ret){
        // printf("[+] Callocated new object at 0x%x with size %d\n", r0, calloc_size);
        k.allocated_obj_k = r0;
        v.allocated_obj_v = calloc_size;
        allocated_objects = SetValueInMap(k, v, allocated_objects);
        update_free_list(r0, calloc_size);

        calloc_ret = 0;
        calloc_size = 0;
    }

    if (pc == realloc_ret)
    {
        // printf("[+] Rellocated new object at 0x%x with size %d\n", r0, realloc_size);
        k.allocated_obj_k = realloc_obj;
        allocated_objects = EraseByKeyMap(k, allocated_objects);
        k.allocated_obj_k = r0;
        v.allocated_obj_v = realloc_size;
        allocated_objects = SetValueInMap(k, v, allocated_objects);
        update_free_list(r0, realloc_size);

        realloc_ret  = 0;
        realloc_obj  = 0;
        realloc_size = 0;
    }

    if (pc == free_ret)
    {
        if (free_obj != 0)
        {
            int isDetected = 0;
            vector *fobj = freed_objects;
            for (; fobj != NULL; fobj = fobj->next)
            {
                if (fobj->item.freed_obj == free_obj)
                {
                    printf("[!] Detected double free vulnerability, invalid attempt to free object at %x\n", free_obj);
                    isDetected = 1;
                    break;
                }
            }
            if (!isDetected)
            {
                // printf("[+] Free'd object at at 0x%x\n", free_obj);
                k.allocated_obj_k = free_obj;
                allocated_objects = EraseByKeyMap(k, allocated_objects);
                
                vector_item vi;
                vi.freed_obj = free_obj;
                freed_objects = PushBackVector(vi, freed_objects);
            }
        }
        free_ret = 0;
        free_obj = 0;
    }
    return 0;
}


static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *op)
{
    const TCGOpcode opc = op->opcode->opc;
    uint64_t pc = op->pc;

    // detect load/store
    switch (opc)
    {
    // load/store from guest memory
    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_st_i32:
        break;
    default:
        return;
    }

    const TCGMemOpIdx flags = op->opargs[2];
    const TCGMemOp memflags = get_memop(flags);
    uint32_t memory_size = memory_op_size(memflags);

    CPUArchState *env = tpi_current_cpu_arch(tpi);
    TCGv_ptr t_env = tcg_const_ptr(env);
    TCGv_i64 t_pc = tcg_const_i64(pc);
    TCGArg addr = op->opargs[1];
    TCGv_i32 t_size = tcg_const_i32(memory_size);

    TCGTemp *args[] = {tcgv_ptr_temp(t_env), tcgv_i64_temp(t_pc),
                       arg_temp(addr), tcgv_i32_temp(t_size)};

    tcg_gen_callN(phys_mem_write_heapobject_cb, TCG_CALL_DUMMY_ARG,
                      sizeof(args) / sizeof(args[0]), args);

    tcg_temp_free_ptr(t_env);
    tcg_temp_free_i64(t_pc);
    tcg_temp_free_i32(t_size);
}


void before_block_exec_heapobject_cb(const TCGPluginInterface *tpi)
{
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    target_ulong r0 = env->regs[0];
    target_ulong r1 = env->regs[1];
    target_ulong r2 = env->regs[2];
    target_ulong lr = env->regs[14];
    target_ulong pc = env->regs[15];

    if (pc == malloc_addr || (pc == malloc_r_addr && !malloc_ret))
    {
        malloc_ret = lr - lr % 2;
        malloc_size = pc == malloc_addr ? r0 : r1;
    }

    if (pc == calloc_addr)
    {
        calloc_ret = lr - lr % 2;
        calloc_size = r0 * r1;
    }

    if (pc == realloc_addr || (pc == realloc_r_addr && !realloc_ret))
    {
        realloc_ret  = lr - lr % 2;
        realloc_obj  = pc == realloc_addr ? r0 : r1;
        realloc_size = pc == realloc_addr ? r1 : r2;
    }
    if (pc == free_addr || (pc == free_r_addr && !free_ret))
    {
        free_ret = lr - lr % 2;
        free_obj = pc == free_addr ? r0 : r1;
    }
}


#define GET_ADDR_OPT(argname, envname) do {        \
    tempenv = getenv(argname);                     \
    if (tempenv == NULL)                           \
        envname = 0;                               \
    else                                           \
        envname = strtoul(tempenv, NULL, 10);      \
    /* printf("%-10s = 0x%08x\n", argname, envname);*/  \ 
} while (0);


void tpi_init(TCGPluginInterface *tpi)
{
    char *tempenv; // macro GET_ADDR_OPT should use it.    
    GET_ADDR_OPT("malloc", malloc_addr);
    GET_ADDR_OPT("realloc", realloc_addr);
    GET_ADDR_OPT("free", free_addr);
    GET_ADDR_OPT("calloc", calloc_addr);
    GET_ADDR_OPT("malloc_r", malloc_r_addr);
    GET_ADDR_OPT("realloc_r", realloc_r_addr);
    GET_ADDR_OPT("free_r", free_r_addr);

    TPI_INIT_VERSION(tpi);
    TPI_DECL_FUNC_4(tpi, phys_mem_write_heapobject_cb, void, ptr, i64, i64, i64);
    tpi->before_exec_tb = before_block_exec_heapobject_cb;
    tpi->after_exec_tb = after_block_exec_heapobject_cb;
    tpi->after_gen_opc = after_gen_opc;

    printf("Init plugin heapobject_tracking!\n");
}
