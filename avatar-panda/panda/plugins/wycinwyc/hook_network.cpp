#include "hook_network.h"
#ifdef TARGET_ARM
static uint32_t cur_seed_num;
static char local_seed_path[256];
static char local_gvfile_path[256];

typedef int (*qi_hnb)(void);
qi_hnb hit_new_bits;
qi_hnb get_bitmap_size;

typedef void (*c_call_py_str_none)(const char*, const char*, const char*);
c_call_py_str_none String_NoRet;
typedef unsigned char *(*c_call_py_StrAndInt_u8ptr)(const char*, const char*, const char*, const int, const int);
c_call_py_StrAndInt_u8ptr StrAndInt_u8ptr;


#define random(x) (rand()%x)
uint8_t *no_mut_seed;


uint8_t *gen_one(uint32_t length) {
    uint8_t *ret = (uint8_t*)malloc(sizeof(uint8_t)*length);
    for (uint32_t i = 0; i < length; i++) {
        *(ret+i) = (uint8_t)random(255); 
    }
    return ret;
}


void hexdump(uint8_t *buf, uint32_t len) {
    for (int i = 0; i < len; i++) {
        if (i != 0 && i % 16 == 0) {
            printf("\n");
        }
        printf("%02x ", *(buf+i));
    }
    printf("\n");
}


bool replace_net_fun(CPUState *cpu, TranslationBlock *tb) {  
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    // hook net func
    if (tb->pc <= 0) {
        printf("this shouldnt happen\n");
        return false;
    }
    else if(tb->pc == net_fun_addr) {
        printf("hit network pc: 0x%08x\n", tb->pc);
        String_NoRet("fuzz", "update_gpq", local_gvfile_path);

        // get parameters
        uint32_t r0 = env->regs[buf_reg_index];
        uint32_t r1 = env->regs[len_reg_index];
        r1 = r1 < 1 ? 1 : r1; // avoid r1=0
        int maxlen = r1;

#if 0
        uint8_t *mut_buf = no_mut_seed;
        int reallen = maxlen;
#endif
        int is_hit = hit_new_bits();
        unsigned char *mut_buf = StrAndInt_u8ptr("mutator", "pass_buf_to_Cpp", local_seed_path, maxlen, is_hit);
        int reallen = 0;
        memcpy(&reallen, mut_buf, sizeof(int));
        printf("recive len is %d\n", reallen);
        hexdump(mut_buf+sizeof(int), reallen);
        reallen = reallen <= r1 ? reallen : r1;

        // do something replace ret
        // write buf into regs[buf_reg_index]
        if(0 == panda_virtual_memory_rw(cpu, r0, mut_buf+sizeof(int), reallen, 1))
            printf("buffer write done\n");
        // set return value
        env->regs[0] = 0; // void function return 0
        // printf("length write done\n");
        // set pc
        uint32_t ret_addr = (env->regs[14] & (~(uint32_t)0 << 1));
        env->regs[15] = ret_addr;

        free(mut_buf);

        return true;
    }
    else {
        return false;
    }
}


bool enable_hook_network(void *self, panda_cb pcb) {
    printf("\nInit plugin hook_network!\n");

    strcpy(local_seed_path, seed_path);
    strcpy(local_gvfile_path, gvfile_path);
    
    hit_new_bits = (qi_hnb)dlsym(QemuInterface_so_handle, "hit_new_bits");
    if(!hit_new_bits) {
        printf("load hit_new_bits error!\n");
        printf("%s\n", dlerror());
        dlclose(QemuInterface_so_handle);
        return false;
    }
    get_bitmap_size = (qi_hnb)dlsym(QemuInterface_so_handle, "get_bitmap_size");
    if(!get_bitmap_size) {
        printf("load get_bitmap_size error!\n");
        printf("%s\n", dlerror());
        dlclose(QemuInterface_so_handle);
        return false;
    }

    String_NoRet = (c_call_py_str_none)dlsym(ccallpy_so_handle, "String_NoRet");
    if(!String_NoRet) {
        printf("load String_NoRet error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return false;
    }
    StrAndInt_u8ptr = (c_call_py_StrAndInt_u8ptr)dlsym(ccallpy_so_handle, "StrAndInt_u8ptr");
    if(!StrAndInt_u8ptr) {
        printf("load StrAndInt_u8ptr error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return false;
    }

    String_NoRet("mutator", "init_seed_status", local_seed_path);
    // no_mut_seed = gen_one(1500+sizeof(int));

    pcb.before_block_exec_invalidate_opt = replace_net_fun;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

    return true;
}

#endif
