#include "wycinwyc.h"


#ifdef TARGET_ARM

std::map<target_ulong, std::vector<cs_insn>> tb_insns_map;
std::vector<memory_range> mappings;

target_ulong printf_addr;
target_ulong fprintf_addr;
target_ulong dprintf_addr;
target_ulong sprintf_addr; 
target_ulong snprintf_addr;
target_ulong malloc_addr;
target_ulong malloc_r_addr;
target_ulong realloc_addr;
target_ulong realloc_r_addr;
target_ulong free_addr;
target_ulong free_r_addr;
target_ulong calloc_addr;

target_ulong net_fun_addr;
const char *seed_path;
const char *gvfile_path;
uint32_t buf_reg_index;
uint32_t len_reg_index;
std::map<target_ulong, target_long> bypass_func_addr_map_ret; // reture value can be negative num
std::map<target_ulong, target_long> bypass_bb_addr_map_addr; // pc must positive num, but for same interface, so treat as signed
// hook_network call .so
void *QemuInterface_so_handle;
void *ccallpy_so_handle;
typedef int (*c_call_py_init_and_uninit)(void);
c_call_py_init_and_uninit Init_Py;
c_call_py_init_and_uninit Uninit_Py;

// Parse string of delimited arguments to map
void args_to_map(const char *arg_list_str, std::map<target_ulong, target_long> & out) {
    if ((!arg_list_str)) { 
        return; 
    }

    std::string s(arg_list_str);
    std::string delimkk("~");
    std::string delimkv(":");

    out.clear();
    size_t pos_start_kk = 0, pos_end_kk = s.find(delimkk), len_kk = 0;
    size_t pos_start_v = 0, pos_end_kv = s.find(delimkv), len_k = 0, len_v = 0;

    target_ulong key;
    target_long value;
    // 1 arg, no delimkk
    if (pos_end_kk == std::string::npos) {
        len_k = (pos_end_kv - pos_start_kk);
        key = (target_ulong)std::stoul(s.substr(pos_start_kk, len_k), nullptr, 10);
        pos_start_v = pos_end_kv + delimkv.size();
        len_v = (pos_end_kk - pos_start_v);
        value = (target_long)std::stol(s.substr(pos_start_v, len_v), nullptr, 10);
        out[key] = value;
        return;
    }

    // Delimited args
    while (pos_end_kk != std::string::npos) {
        len_k = (pos_end_kv - pos_start_kk);
        key = (target_ulong)std::stoul(s.substr(pos_start_kk, len_k), nullptr, 10);
        pos_start_v = pos_end_kv + delimkv.size();
        len_v = (pos_end_kk - pos_start_v);
        value = (target_long)std::stol(s.substr(pos_start_v, len_v), nullptr, 10);
        out[key] = value;

        pos_start_kk = (pos_end_kk + delimkk.size());
        pos_end_kk = s.find(delimkk, pos_start_kk);
        pos_end_kv = s.find(delimkv, pos_start_kk);
    }

    // No delimkk after last arg
    if (pos_start_kk < (s.size() - 1)) {
        len_k = (pos_end_kv - pos_start_kk);
        key = (target_ulong)std::stoul(s.substr(pos_start_kk, len_k), nullptr, 10);
        pos_start_v = pos_end_kv + delimkv.size();
        value = (target_long)std::stol(s.substr(pos_start_v), nullptr, 10);
        out[key] = value;
    }
}

int after_block_translate_cb(CPUState *cpu, TranslationBlock *tb) {
    csh handle;
    cs_mode mode;
    cs_insn *insn;
    size_t count;

    if(tb_insns_map.find(tb->pc) != tb_insns_map.end())
        return 0;

    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint8_t * tb_opcodes_buffer = (uint8_t *) malloc(tb->size);  
    panda_virtual_memory_read(cpu, tb->pc, tb_opcodes_buffer, tb->size);


    //wycinwyc-specific: thumb == cortex-m 
    mode = env->thumb ? (cs_mode) (CS_MODE_THUMB + CS_MODE_MCLASS) : CS_MODE_ARM;


    if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Unable to invoke capstone!\n");

        exit(-1);
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, tb_opcodes_buffer, tb->size, tb->pc, 0, &insn);
    //printf("aft %x %x\n", count, tb->size);
    if (count <= 0) {
        fprintf(stderr, "Error during disassembling at " TARGET_FMT_lx, tb->pc);
        exit(-1);
    }

    //for (size_t i = 0; i < count; i++) {
        //printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
    //}
    std::vector<cs_insn> v(insn, insn+count);
    tb_insns_map[tb->pc] = v;

    free(tb_opcodes_buffer);
    free(insn);
    return 1;
}

void enable_capstone_invocation(void *self, panda_cb pcb) {
    pcb.after_block_translate = after_block_translate_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
}


QDict * load_json(const char * filename) {
    int file = open(filename, O_RDONLY);
    off_t filesize = lseek(file, 0, SEEK_END);
    char * filedata = NULL;
    ssize_t err;
    QObject * obj;

    lseek(file, 0, SEEK_SET);

    filedata = (char *) g_malloc(filesize + 1);
    memset(filedata, 0, filesize + 1);

    if (!filedata)
    {
        fprintf(stderr, "%ld\n", filesize);
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    err = read(file, filedata, filesize);

    if (err != filesize)
    {
        fprintf(stderr, "Reading json file %s failed\n", filename);
        exit(1);
    }

    close(file);

    obj = qobject_from_json(filedata);
    if (!obj || qobject_type(obj) != QTYPE_QDICT)
    {
        fprintf(stderr, "Error parsing JSON file %s\n", filename);
        exit(1);
    }

    g_free(filedata);

    return qobject_to_qdict(obj);
}


bool sort_ranges(memory_range a, memory_range b) {
    return (a.address < b.address);
}

void parse_memory_maps_from_file(const char * conf_file) {
    int size, address;
    const char * permissions;
    memory_range range;
    QListEntry * entry;

    QDict * conf = load_json(conf_file);
    if (qdict_haskey(conf, "memory_mapping")) {
        QList * memories = qobject_to_qlist(qdict_get(conf, "memory_mapping"));
        g_assert(memories);

        QLIST_FOREACH_ENTRY(memories, entry) {
            g_assert(qobject_type(entry->value) == QTYPE_QDICT);
            QDict *mapping = qobject_to_qdict(entry->value);
            printf("%s\n", qdict_get_str(mapping, "name"));
            QDICT_ASSERT_KEY_TYPE(mapping, "size", QTYPE_QINT);
            QDICT_ASSERT_KEY_TYPE(mapping, "address", QTYPE_QINT);
            QDICT_ASSERT_KEY_TYPE(mapping, "permissions", QTYPE_QSTRING);

            address = qdict_get_int(mapping, "address");
            size = qdict_get_int(mapping, "size");
            permissions = qdict_get_str(mapping, "permissions");

            range.address = address;
            range.size = size;
            range.perms = 0;
            range.perms |= permissions[0] == 'r' ? 4: 0;
            range.perms |= permissions[1] == 'w' ? 2: 0;
            range.perms |= permissions[2] == 'x' ? 1: 0;

            range.file_backed = qdict_haskey(mapping, "file") ? true : false;
            mappings.push_back(range);
            
        }
        std::sort(mappings.begin(), mappings.end(), sort_ranges);
   }
   free(conf);
}

bool init_hook_network_call_sofile() {
    QemuInterface_so_handle = dlopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/QemuInterface.so", RTLD_LAZY);
    if(!QemuInterface_so_handle) {
        printf("open QemuInterface.so error!\n");
        printf("%s\n", dlerror());
        return false;
    }
    ccallpy_so_handle = dlopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/avatar-panda/panda/plugins/wycinwyc/ccallpythonso.so", RTLD_LAZY | RTLD_GLOBAL);
    if(!ccallpy_so_handle) {
        printf("open ccallpythonso.so error!\n");
        printf("%s\n", dlerror());
        return false;
    }
    Init_Py = (c_call_py_init_and_uninit)dlsym(ccallpy_so_handle, "Init_Py");
    if(!Init_Py) {
        printf("load Init_Py error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return false;
    }
    Uninit_Py = (c_call_py_init_and_uninit)dlsym(ccallpy_so_handle, "Uninit_Py");
    if(!Uninit_Py) {
        printf("load Uninit_Py error!\n");
        printf("%s\n", dlerror());
        dlclose(ccallpy_so_handle);
        return false;
    }
    if(Init_Py() != 1) {
        // error log will output in Init_Py()
        return false;
    }
    return true;
}

bool init_plugin(void *self) {
    panda_cb pcb;
    fprintf(stderr, "init_plugin: before panda_get_args\n");
    panda_arg_list *args = panda_get_args("wycinwyc");
    //const char *analysis_technique = panda_parse_string(args, "technique", NULL);
    bool segment_tracking       = panda_parse_bool_opt(args, "segment", "enable tracking of segments");
    bool callstack_tracking     = panda_parse_bool_opt(args, "callstack", "enable tracking of callstack");
    bool callframe_tracking     = panda_parse_bool_opt(args, "callframe", "enable tracking of callstack");
    bool printf_tracking        = panda_parse_bool_opt(args, "fstring", "");
    bool heapobject_tracking    = panda_parse_bool_opt(args, "heapobjects", "");
    bool stackobject_tracking   = panda_parse_bool_opt(args, "stackobjects", "");
    bool hook_network_tracking  = panda_parse_bool_opt(args, "hooknetwork", "enable hooking of network functions");
    bool div_tracking           = panda_parse_bool_opt(args, "div", "enable tracking of div");
    bool inst_tracking          = panda_parse_bool_opt(args, "inst", "enable tracking of inst execution");
    bool bypass_verify_tracking    = panda_parse_bool_opt(args, "bypassverify", "enable bypass some functions or basic block(like bypass verification of chsum etc. :)");

    const char *conf_file = panda_parse_string_opt(args, "mapfile", "conf.json", "The json file containing memory mappings (normally produced by avatar)");

    panda_enable_precise_pc();
    panda_disable_tb_chaining();

    if (callstack_tracking | heapobject_tracking | segment_tracking | stackobject_tracking) {
        fprintf(stderr, "init_plugin: panda_enable_memcb!\n");        
        panda_enable_memcb();
    }

    if (callstack_tracking | callframe_tracking | stackobject_tracking) {
        fprintf(stderr, "init_plugin: enable_capstone_invocation!\n");
        enable_capstone_invocation(self, pcb);
    }

    if (printf_tracking | segment_tracking) {
        fprintf(stderr, "init_plugin: parse_memory_maps_from_file: %s!\n", conf_file);
        parse_memory_maps_from_file(conf_file);
    }

    
    if (callstack_tracking) {
        fprintf(stderr, "init_plugin: enable_callstack_tracking!\n");
        enable_callstack_tracking(self, pcb);
        printf("Callstack Tracking loaded!\n");
    }

    if (hook_network_tracking) {
        net_fun_addr = panda_parse_ulong_opt(args, "net_fun", 0, "Address of net-function (required for hook_network_tracking");
        seed_path = panda_parse_string_opt(args, "seed_path", "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_hjx/frdmk66f_lwip_httpsrv_bm/seed", "the path saved crash test cases");
        gvfile_path = panda_parse_string_opt(args, "gvfile_path", "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_hjx/frdmk66f_lwip_httpsrv_bm/myavatar/gvfile.txt", "path/to/gvfile.txt");        
        buf_reg_index = panda_parse_uint32_opt(args, "buf_reg_index", 0, "net_hook register index of buf address");
        len_reg_index = panda_parse_uint32_opt(args, "len_reg_index", 1, "net_hook register index of len address");

        if(!init_hook_network_call_sofile()) {
            exit(-1);
        }

        fprintf(stderr, "init_plugin: enable_hook_network!\n");
        enable_hook_network(self, pcb);
        printf("hook_network loaded!\n");
    }

    if (bypass_verify_tracking) {
        const char* bypass_func_str = nullptr;
        const char* bypass_bb_str = nullptr;                
        bypass_func_str = panda_parse_string_opt(args, "bypass_funcs", nullptr, "the addr of funcs which want to just bypass(string, '~' as delimkk, pc:ret_value)");
        bypass_bb_str = panda_parse_string_opt(args, "bypass_basic_blocks", nullptr, "the addr of basic block which want to just bypass(string, '~' as delimkk, pc:pc, eg. verify_err_bb:verify_acc_bb)");
        
        if (bypass_func_str) {
            args_to_map(bypass_func_str, bypass_func_addr_map_ret);
        }

        if (bypass_bb_str) {
            args_to_map(bypass_bb_str, bypass_bb_addr_map_addr);
        }

        fprintf(stderr, "init_plugin: enable_bypass_verification!\n");
        enable_bypass_verification(self, pcb);
        printf("bypass_verification loaded!\n");
    }

    if (callframe_tracking) {
        fprintf(stderr, "init_plugin: enable_callframe_tracking!\n");
        enable_callframe_tracking(self, pcb);
        printf("Callframe Tracking loaded!\n");
    }

    if (printf_tracking) {
        printf_addr = panda_parse_ulong_opt(args, "printf", 0, "Address of printf-function (required for printf_tracking");
        fprintf_addr = panda_parse_ulong_opt(args, "fprintf", 0, "Address of fprintf-function (required for printf_tracking");
        dprintf_addr = panda_parse_ulong_opt(args, "dprintf", 0, "Address of dprintf-function (required for printf_tracking");
        sprintf_addr = panda_parse_ulong_opt(args, "sprintf", 0, "Address of sprintf-function (required for printf_tracking");
        snprintf_addr = panda_parse_ulong_opt(args, "snprintf", 0, "Address of snprintf-function (required for printf_tracking");
        
        if (printf_addr == 0 && fprintf_addr == 0 && dprintf_addr == 0 && 
                sprintf_addr == 0 && snprintf_addr == 0) {
            puts("Provide at least one address of a function from the format-string family as argument!");
            exit(-1);
        }
        fprintf(stderr, "init_plugin: enable_printf_tracking!\n");
        enable_printf_tracking(self, pcb);
        printf("Format Specifier Tracking loaded!\n");
    }

    if (heapobject_tracking) {
        malloc_addr = panda_parse_ulong_opt(args, "malloc", 0, "Address of malloc-function (required for heapobject_tracking");
        realloc_addr = panda_parse_ulong_opt(args, "realloc", 0, "Address of realloc-function (required for heapobject_tracking");
        free_addr = panda_parse_ulong_opt(args, "free", 0, "Address of calloc-function (required for heapobject_tracking");
        calloc_addr = panda_parse_ulong_opt(args, "calloc", 0, "Address of calloc-function (required for heapobject_tracking");
        malloc_r_addr = panda_parse_ulong_opt(args, "malloc_r", 0, "Address of reentrant malloc-function (required for heapobject_tracking");
        realloc_r_addr = panda_parse_ulong_opt(args, "realloc_r", 0, "Address of realloc-function (required for heapobject_tracking");
        free_r_addr = panda_parse_ulong_opt(args, "free_r", 0, "Address of reentrant free-function (required for heapobject_tracking");

        fprintf(stderr, "init_plugin: enable_heapobject_tracking!\n");
        enable_heapobject_tracking(self, pcb);
        printf("Heapobject Tracking loaded!\n");
    }

    if (segment_tracking) {
        fprintf(stderr, "init_plugin: enable_segment_tracking!\n");
        enable_segment_tracking(self, pcb);
        printf("Segment Tracking loaded!\n");
    }

    if(stackobject_tracking) {
        const char *debug_symbol_file = panda_parse_string_opt(args, "debugfile", "funcs.json", "File with jsonized debug_symbols");
        fprintf(stderr, "init_plugin: enable_stackobject_tracking!\n");
        enable_stackobject_tracking(self, pcb, debug_symbol_file);
        printf("Stackobject Tracking loaded!\n");
    }

    if(div_tracking) {
        fprintf(stderr, "init_plugin: enable_div_tracking!\n");
        enable_div_tracking(self, pcb);
        printf("Div Tracking loaded!\n");
    }

    if(inst_tracking) {
        fprintf(stderr, "init_plugin: enable_inst_tracking!\n");
        enable_inst_tracking(self, pcb);
        printf("Inst Tracking loaded!\n");
    }

    panda_free_args(args);
    printf("Initialized! :)\n");
    return true;
}


void uninit_plugin(void *self) {
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
    printf("UnInitialized! :)\n");
}

#endif
