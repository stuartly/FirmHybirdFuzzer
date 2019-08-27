#include <stdio.h>
#include <stdlib.h>
#include "tcg-plugin.h"
#include "wycinwyc.h"
#include "stl/vector.h"
#include "stl/cJSON.h"

// vector * mappings; // mappings.item.memory_range

#define DEBUG_NOMAP 0

vector *load_json(const char *filename)
{
	// read data from file
	FILE *fp = fopen(filename, "r");
	if (fp == NULL)
	{
		printf("file %s open failed.\n", filename);
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	int filesize = ftell(fp);
	// printf("filesize %d\n", filesize);
	char *filedata = NULL;

	fseek(fp, 0, SEEK_SET);

	filedata = (char *)malloc(filesize + 1);
	fread(filedata, sizeof(char), filesize+1, fp);
	// printf("%s\n", filedata);
	fclose(fp);

	// map json to struct memory_mapping
	vector *root = (vector *)malloc(sizeof(vector));
	root->next = NULL;
	vector *pre_node = root;

	cJSON *pJson = cJSON_Parse(filedata);
	cJSON *mem_map = cJSON_GetObjectItem(pJson, "memory_mapping");

	// int n = cJSON_GetArraySize(mem_map);
    // cJSON *men = cJSON_GetArrayItem(mem_map, i);
	cJSON *mem = NULL;
    cJSON_ArrayForEach(mem, mem_map)
	{
		int address = cJSON_GetObjectItem(mem, "address")->valueint;
		// printf("address %d\n", address);
		int size = cJSON_GetObjectItem(mem, "size")->valueint;
		char *perms_str = cJSON_GetObjectItem(mem, "permissions")->valuestring;
		char perms = 0;
		perms += perms_str[0] == 'r' ? 1 : 0;
		perms += perms_str[1] == 'w' ? 2 : 0;
		perms += perms_str[2] == 'x' ? 4 : 0;
		// printf("perms %s %d\n", perms_str, perms);
		// bool file_backed;
		int file_backed = cJSON_GetObjectItem(mem, "file") == NULL ? 0 : 1;
		// printf("file_backed %d\n", file_backed);
		pre_node->next = (vector *)malloc(sizeof(vector));
		if (pre_node->next != NULL)
		{
            vector *new_node = pre_node->next;
            memory_range new_mr;
            new_mr.address = address;
            new_mr.size = size;
            new_mr.perms = perms;
            new_mr.file_backed = file_backed;
            vector_item vit1;
            vit1.mr = new_mr;
            new_node->item = vit1;
			new_node->next = NULL;
			pre_node = new_node;
		}
	}

    cJSON_Delete(pJson);
	vector *ret = root->next;
	free(root);
    free(filedata);
    BubbleSortVector(ret);
    // PrintVector(ret);
	return ret;
}

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

void phys_mem_write_segment_cb(CPUArchState *env, target_ulong pc, target_ulong addr, target_ulong size)
{
    target_ulong env_pc = env->regs[15];
    vector *m = mappings;
    for (; m != NULL; m = m->next)
    {
        if (m->item.mr.address > addr + size)
            break;

        if ((m->item.mr.address < addr + size) && (addr + size < m->item.mr.address + m->item.mr.size))
        {
            if (!(m->item.mr.perms & 2))
            {
                printf("[!] Found write to non-readable address (0x%08x) at pc=0x%08x\n", addr, env_pc);
            }
            else
            {
                return;
            }
        }
    }
#if DEBUG_NOMAP
    printf("[!] Found write to non-mapped address (0x%08x) at pc=0x%08x\n", addr, env_pc);
#endif
}

void phys_mem_read_segment_cb(CPUArchState *env, target_ulong pc, target_ulong addr, target_ulong size)
{
    target_ulong env_pc = env->regs[15];
    vector *m = mappings;
    for (; m != NULL; m = m->next)
    {
        if (m->item.mr.address > addr + size)
            break;

        if ((m->item.mr.address < addr + size) && (addr + size < m->item.mr.address + m->item.mr.size))
        {
            if (!(m->item.mr.perms & 4))
            {
                printf("[!] Found read from non-readable address (0x%08x) at pc=0x%08x\n", addr, env_pc);
            }
            else
            {
                return;
            }
        }
    }
#if DEBUG_NOMAP
    printf("[!] Found read from non-mapped address (0x%08x) at pc=0x%08x\n", addr, env_pc);
#endif
}

static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *op)
{
    const TCGOpcode opc = op->opcode->opc;
    uint64_t pc = op->pc;

    int is_load = 0;

    // detect load/store
    switch (opc)
    {
    // load/store from guest memory
    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        is_load = 1;
        break;
    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_st_i32:
        is_load = 0;
        break;
    default:
        return;
    }

    const TCGMemOp memflags = get_memop(op->opargs[2]);
    uint32_t memory_size = memory_op_size(memflags);

    CPUArchState *env = tpi_current_cpu_arch(tpi);
    TCGv_ptr t_env = tcg_const_ptr(env);
    TCGv_i64 t_pc = tcg_const_i64(pc);
    TCGArg addr = op->opargs[1];
    TCGv_i32 t_size = tcg_const_i32(memory_size);

    TCGTemp *args[] = {tcgv_ptr_temp(t_env), tcgv_i64_temp(t_pc),
                       arg_temp(addr), tcgv_i32_temp(t_size)};

    if (is_load)
    {
        tcg_gen_callN(phys_mem_read_segment_cb, TCG_CALL_DUMMY_ARG,
                      sizeof(args) / sizeof(args[0]), args);
    }
    else
    {
        tcg_gen_callN(phys_mem_write_segment_cb, TCG_CALL_DUMMY_ARG,
                      sizeof(args) / sizeof(args[0]), args);
    }

    tcg_temp_free_ptr(t_env);
    tcg_temp_free_i64(t_pc);
    tcg_temp_free_i32(t_size);
}

void tpi_init(TCGPluginInterface *tpi)
{
    // memory_range mr1 = {1610612736, 2097152, 5, 1};
    // memory_range mr2 = {0, 2097152, 5, 1};
    // memory_range mr3 = {536805376, 262144, 6, 0};
    // memory_range mr4 = {2684289024, 262144, 6, 0};
    // memory_range mr5 = {1073741824, 1342177280, 6, 0};
    // // PrintVector(mappings);

    // vector_item vit;
    // vit.mr = mr1;
    // mappings = CreateNodeVector(vit);
    // vit.mr = mr2;
    // mappings = PushBackVector(vit, mappings);
    // vit.mr = mr3;
    // mappings = PushBackVector(vit, mappings);
    // vit.mr = mr4;
    // mappings = PushBackVector(vit, mappings);
    // vit.mr = mr5;
    // mappings = PushBackVector(vit, mappings);
    // PrintVector(mappings);
    // vector* mapend = GetVectorEnd(mappings);
    // QuickSortVector(mappings, mapend);
    const char *conffile;
    conffile = getenv("CONF_FILE");
    if(conffile == NULL)
    {
        printf("[-] env CONF_FILE=/abs/path/to/conf.json command");
        return 0;
    }
    mappings = load_json(conffile);
    // PrintVector(mappings);
    if(!mappings)
    {
        printf("[-] Can't open mapping file!\n");
        return 0;
    }
    
    TPI_INIT_VERSION(tpi);
    TPI_DECL_FUNC_4(tpi, phys_mem_write_segment_cb, void, ptr, i64, i64, i64);
    TPI_DECL_FUNC_4(tpi, phys_mem_read_segment_cb, void, ptr, i64, i64, i64);
    tpi->after_gen_opc = after_gen_opc;
    
    printf("Init plugin segment_tracking!\n");
}
