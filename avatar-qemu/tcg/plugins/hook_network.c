#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>
#include "tcg-plugin.h"
#include "wycinwyc.h"
// #ifdef TARGET_ARM

static target_ulong net_fun_addr;
static uint32_t buf_reg_index;
static uint32_t len_reg_index;
static char *seed_path;
static char *gvfile_path;
static bool is_mut;

// hook_network call .so
// so_handle init in init_hook_network_call_sofile(), uninit in cpus_stopped
void *QemuInterface_so_handle;
void *ccallpy_so_handle;
typedef int (*c_call_py_init_and_uninit)(void);
c_call_py_init_and_uninit Init_Py;
c_call_py_init_and_uninit Uninit_Py;

typedef int (*qi_hnb)(void);
qi_hnb hit_new_bits;
qi_hnb get_bitmap_size;

typedef void (*c_call_py_str_none)(const char*, const char*, const char*);
c_call_py_str_none String_NoRet;

typedef unsigned char *(*c_call_py_StrAndInt_u8ptr)(const char*, const char*, const char*, const int, const int);
c_call_py_StrAndInt_u8ptr StrAndInt_u8ptr;

#define LWIP_RECVFROM

#define random(x) (rand()%x)
#define MAX_PACKET_LEN 1500
#define SHADOW_MEM_LEN sizeof(int)
uint8_t *no_mut_seed;


uint8_t *gen_one(uint32_t length) {
    uint8_t *ret = (uint8_t*)malloc(sizeof(uint8_t)*length);
    for (uint32_t i = 0; i < length; i++) {
        srand((unsigned)time(NULL));
        *(ret+i) = (uint8_t)random(255); 
    }
    return ret;
}

uint8_t *gen_0(uint32_t length) {
    uint8_t *ret = (uint8_t*)malloc(sizeof(uint8_t)*length);
    memset(ret, 0, sizeof(uint8_t)*length);
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


int replace_net_fun(const TCGPluginInterface *tpi)
{  
    CPUArchState *env = tpi_current_cpu_arch(tpi);
    CPUState *cpu = tpi_current_cpu(tpi);
    TranslationBlock *cur_tb = tpi->tb;
    // hook net func
    if (cur_tb->pc <= 0) {
        printf("this shouldnt happen\n");
        return 0;
    }
    else if(cur_tb->pc == net_fun_addr) {
        printf("hit network pc: 0x%08x\n", cur_tb->pc);
        String_NoRet("fuzz", "update_gpq", gvfile_path);

        // get parameters
        uint32_t r0 = env->regs[buf_reg_index];
        uint32_t r1 = env->regs[len_reg_index];
        r1 = r1 < 1 ? 1 : r1; // avoid r1=0
        int reallen = 0;
        uint8_t *mut_buf = NULL;

        if (is_mut == false) {
            mut_buf = no_mut_seed;
            reallen = r1;
        }
        else {
            int is_hit = hit_new_bits();
            mut_buf = StrAndInt_u8ptr("mutator", "pass_buf_to_Cpp", seed_path, r1, is_hit);
            memcpy(&reallen, mut_buf, SHADOW_MEM_LEN);
            printf("recive len is %d\n", reallen);
            // hexdump(mut_buf+SHADOW_MEM_LEN, reallen);
            reallen = reallen <= r1 ? reallen : r1;
        }

        // do something replace ret
        // write buf into regs[buf_reg_index]
        if(0 == qemu_virtual_memory_rw(cpu, r0, mut_buf+SHADOW_MEM_LEN, reallen, 1))
            printf("buffer write done\n");
        // set return value
        env->regs[0] = 0; // void function return 0
#ifdef LWIP_RECVFROM
        srand((unsigned)time(NULL));
        env->regs[0] = random(2) ? reallen : 0;
#endif
        // printf("length write done\n");
        // set pc
        uint32_t ret_addr = (env->regs[14] & (~(uint32_t)0 << 1));
        env->regs[15] = ret_addr;

        if (is_mut == true) {
            free(mut_buf);
        }
  
        return 1;
    }
    else {
        return 0;
    }
}

void uninit_plugin(const TCGPluginInterface *tpi)
{
    if(QemuInterface_so_handle != NULL) {
        printf("Close QemuInterface_so_handle\n");
        dlclose(QemuInterface_so_handle);
    }
    if(ccallpy_so_handle != NULL) {
        printf("Close c call Python\n");
        Uninit_Py();
        printf("Close ccallpy_so_handle\n");
        dlclose(ccallpy_so_handle);;
    }
    if (is_mut == false) {
        free(no_mut_seed);
    }
    printf("UnInitialized! :)\n\n");
}

#define GET_ENV(argname, help) do {                               \
    tempenv = getenv(argname);                                    \
    if (tempenv == NULL)                                          \
    {                                                             \
        printf("[-] arg '%s' is required! -- %s", argname, help); \
        printf("    use command: env %s=xxx\n", argname);         \
        return 0;                                                 \
    }                                                             \
}while(0);

int get_args() {
    // get args(getenv)
    char *tempenv; // macro GET_ENV should use it.

    // require args
    GET_ENV("NET_FUN_ADDR", "Address of net-function (required for hook_network_tracking");
    net_fun_addr = strtoul(tempenv, NULL, 10);
//    printf("net_fun_addr=0x%x\n", net_fun_addr);

    GET_ENV("BUF_REG_INDEX", "net_hook register index of buf address");
    buf_reg_index = atoi(tempenv);

    GET_ENV("LEN_REG_INDEX", "net_hook register index of len address");
    len_reg_index = atoi(tempenv);
//    printf("buf_reg_index=%d, len_reg_index=%d\n", buf_reg_index, len_reg_index);

    GET_ENV("SEED_PATH", "the path saved seed test cases");
    seed_path = tempenv;
//    printf("seed_path=%s\n", seed_path);

    GET_ENV("GVFILE_PATH", "path/to/gvfile.txt");
    gvfile_path = tempenv;
//    printf("gvfile_path=%s\n", gvfile_path);

    // optional args
    // by default, if this arg doesn't offer, it means true
    tempenv = getenv("IS_MUT");
    if (tempenv != NULL && strcmp(tempenv, "false") == 0) {
//        printf("is_mut=false\n");
        is_mut = false;
    }
    else {
//        printf("is_mut=true\n");
        is_mut = true;
    }
    
    return 1;
}

int init_hook_network_call_sofile()
{
    QemuInterface_so_handle = dlopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/QemuInterface.so", RTLD_LAZY);
    if(!QemuInterface_so_handle) {
        printf("open QemuInterface.so error!\n");
        printf("%s\n", dlerror());
        return 0;
    }
    ccallpy_so_handle = dlopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/avatar-qemu/tcg/plugins/ccallpythonso.so", RTLD_LAZY | RTLD_GLOBAL);
    if(!ccallpy_so_handle) {
        printf("open ccallpythonso.so error!\n");
        printf("%s\n", dlerror());
        return 0;
    }
    Init_Py = (c_call_py_init_and_uninit)dlsym(ccallpy_so_handle, "Init_Py");
    if(!Init_Py) {
        printf("load Init_Py error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return 0;
    }
    Uninit_Py = (c_call_py_init_and_uninit)dlsym(ccallpy_so_handle, "Uninit_Py");
    if(!Uninit_Py) {
        printf("load Uninit_Py error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return 0;
    }
        hit_new_bits = (qi_hnb)dlsym(QemuInterface_so_handle, "hit_new_bits");
    if(!hit_new_bits) {
        printf("load hit_new_bits error!\n");
        printf("%s\n", dlerror());
        dlclose(QemuInterface_so_handle);
        return 0;
    }
    get_bitmap_size = (qi_hnb)dlsym(QemuInterface_so_handle, "get_bitmap_size");
    if(!get_bitmap_size) {
        printf("load get_bitmap_size error!\n");
        printf("%s\n", dlerror());
        dlclose(QemuInterface_so_handle);
        return 0;
    }

    String_NoRet = (c_call_py_str_none)dlsym(ccallpy_so_handle, "String_NoRet");
    if(!String_NoRet) {
        printf("load String_NoRet error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return 0;
    }
    StrAndInt_u8ptr = (c_call_py_StrAndInt_u8ptr)dlsym(ccallpy_so_handle, "StrAndInt_u8ptr");
    if(!StrAndInt_u8ptr) {
        printf("load StrAndInt_u8ptr error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return 0;
    }
    if(Init_Py() != 1) {
        // error log will output in Init_Py()
        return 0;
    }
    return 1;
}

void tpi_init(TCGPluginInterface *tpi)
{
    if (1 != get_args()) {
        printf("[-] Err in get args!\n");
        return;
    }
    if (1 != init_hook_network_call_sofile()) {
        printf("[-] Err in init .so file!\n");
        return;
    }

    printf("Init plugin hook_network!\n");

    if (is_mut == false) {
        no_mut_seed = gen_0(MAX_PACKET_LEN+SHADOW_MEM_LEN);
    }
    else {
        String_NoRet("mutator", "init_seed_status", seed_path);
    }

    tpi->before_exec_tb_invalidate_opt = replace_net_fun;
    tpi->cpus_stopped = uninit_plugin;
}

// #endif
