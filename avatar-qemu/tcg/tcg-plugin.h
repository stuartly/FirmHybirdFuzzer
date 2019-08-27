
/*
 * QEMU TCG plugin support.
 *
 * Copyright (C) 2011 STMicroelectronics
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TCG_PLUGIN_H
#define TCG_PLUGIN_H

#include "qemu/osdep.h" /* CONFIG_TCG, CONFIG_TCG_PLUGIN */

#ifdef CONFIG_TCG_PLUGIN

#include <glib.h>

#include "qemu-common.h"
#include "qom/cpu.h"

#include "tcg.h"
#include "tcg-op.h"
/* must be included after "tcg.h" */
#include "exec/exec-all.h" /* TranslationBlock */

#ifndef CONFIG_TCG
#  error "CONFIG_TCG_PLUGIN is defined, but CONFIG_TCG is not"
#endif

#if TARGET_LONG_BITS == 32
#define MAKE_TCGV MAKE_TCGV_I32
#else
#define MAKE_TCGV MAKE_TCGV_I64
#endif

/***********************************************************************
 * Hooks inserted into QEMU here and there.
 */
  bool tcg_plugin_enabled(void);
  void tcg_plugin_load(const char *name);
  void tcg_plugin_initialize_all(void);
  void tcg_plugin_cpus_stopped(void);
  void tcg_plugin_before_gen_tb(TranslationBlock *tb);
  void tcg_plugin_after_gen_tb(TranslationBlock *tb);
  int tcg_plugin_before_exec_tb_invalidate_opt(TranslationBlock *tb);  // hjx
  void tcg_plugin_before_exec_tb(TranslationBlock *tb);  //situ
  void tcg_plugin_after_exec_tb(TranslationBlock *tb);   //situ
  void tcg_plugin_before_decode_first_instr(TranslationBlock *tb);
  void tcg_plugin_after_decode_last_instr(TranslationBlock *tb);
  void tcg_plugin_before_decode_instr(uint64_t pc);
  void tcg_plugin_after_gen_opc(TCGOp *opcode, uint8_t nb_args);
  const char *tcg_plugin_get_filename(void);

/***********************************************************************
 * TCG plugin interface.
 */

extern bool tcg_plugin_treat_command(const char *command, char **answer);

/* This structure shall be 64 bits, see call_tb_helper_code() for
 * details.  */
typedef struct {
    uint16_t cpu_index;
    uint16_t size;
    union {
        char type;
        uint32_t icount;
    };
} __attribute__((__packed__, __may_alias__)) TPIHelperInfo;

#define TPI_MAX_OP_ARGS 6
typedef struct TPIOpCode {
    uint64_t pc;
    uint8_t nb_args;
    uint8_t operator;
    uint16_t cpu_index;

    TCGOp *opcode;
    TCGArg *opargs;

    /* Should be used by the plugin only.  */
    void *data;
} TPIOpCode;

enum TPI_PARAM_TYPE {
    TPI_PARAM_TYPE_BOOL,
    TPI_PARAM_TYPE_INT,
    TPI_PARAM_TYPE_UINT,
    TPI_PARAM_TYPE_STRING,
    TPI_PARAM_TYPE_DOUBLE,
};

typedef struct {
    char *name;
    enum TPI_PARAM_TYPE type;
    void *value_ptr;
    char *description;
} TPIParam;

struct TCGPluginInterface;
typedef struct TCGPluginInterface TCGPluginInterface;

typedef void (* tpi_cpus_stopped_t)(const TCGPluginInterface *tpi);

typedef void (* tpi_before_gen_tb_t)(const TCGPluginInterface *tpi);

typedef void (* tpi_after_gen_tb_t)(const TCGPluginInterface *tpi);

typedef int (* tpi_before_exec_tb_invalidate_opt_t)(const TCGPluginInterface *tpi);  // hjx

typedef void (* tpi_before_exec_tb_t)(const TCGPluginInterface *tpi);  //situ

typedef void (* tpi_after_exec_tb_t)(const TCGPluginInterface *tpi);   //situ

typedef void (* tpi_before_decode_first_instr_t)(const TCGPluginInterface *tpi,
                                                 const TranslationBlock *tb);

typedef void (* tpi_after_decode_last_instr_t)(const TCGPluginInterface *tpi,
                                               const TranslationBlock *tb);

typedef void (* tpi_before_decode_instr_t)(const TCGPluginInterface *tpi,
                                           uint64_t pc);

typedef void (* tpi_after_gen_opc_t)(const TCGPluginInterface *tpi,
                                     const TPIOpCode *opcode);

typedef void (* tpi_pre_tb_helper_code_t)(const TCGPluginInterface *tpi,
                                          TPIHelperInfo info, uint64_t address,
                                          uint64_t data1, uint64_t data2,
                                          const TranslationBlock *tb);

typedef void (* tpi_pre_tb_helper_data_t)(const TCGPluginInterface *tpi,
                                          TPIHelperInfo info, uint64_t address,
                                          uint64_t *data1, uint64_t *data2,
                                          const TranslationBlock *tb);

/* callback to get access to a parameter.
 * Allows a plugin to compute dynamically a value when parameter is asked.
 * If false is returned, value is read from location given at parameter
 * declaration. */
typedef bool (*tpi_get_param_bool_t)(const TCGPluginInterface *tpi,
                                     const char *name, bool *value);
typedef bool (*tpi_get_param_uint_t)(const TCGPluginInterface *tpi,
                                     const char *name, uint64_t *value);
typedef bool (*tpi_get_param_int_t)(const TCGPluginInterface *tpi,
                                    const char *name, int64_t *value);
typedef bool (*tpi_get_param_string_t)(const TCGPluginInterface *tpi,
                                       const char *name, char **value);
typedef bool (*tpi_get_param_double_t)(const TCGPluginInterface *tpi,
                                       const char *name, double *value);

/* callback to check if new value of a parameter is correct. */
typedef bool (*tpi_check_param_bool_t)(const TCGPluginInterface *tpi,
                                       const char *name,
                                       bool old_value,
                                       bool new_value,
                                       char **error);

typedef bool (*tpi_check_param_int_t)(const TCGPluginInterface *tpi,
                                      const char *name,
                                      int64_t old_value,
                                      int64_t new_value,
                                      char **error);

typedef bool (*tpi_check_param_uint_t)(const TCGPluginInterface *tpi,
                                       const char *name,
                                       uint64_t old_value,
                                       uint64_t new_value,
                                       char **error);

typedef bool (*tpi_check_param_string_t)(const TCGPluginInterface *tpi,
                                         const char *name,
                                         const char *old_value,
                                         const char *new_value,
                                         char **error);

typedef bool (*tpi_check_param_double_t)(const TCGPluginInterface *tpi,
                                         const char *name,
                                         double old_value,
                                         double new_value,
                                         char **error);

/* callback called when plugin was set active/inactive */
typedef void (*tpi_active_changed_t)(bool new_state);

#define TPI_VERSION 9

struct TCGPluginInterface {
    /* Compatibility information.  */
    int32_t version;
    int32_t id;
    const char *name;
    const char *path_name;
    const char *instance_path_name;
    void *instance_handle;
    const char *guest;
    const char *mode;
    size_t sizeof_CPUState;
    size_t sizeof_TranslationBlock;
    size_t sizeof_TCGContext;

    /* Common parameters.  */
    TCGContext *tcg_ctx;
    int nb_cpus;
    FILE *output;
    uint64_t low_pc;
    uint64_t high_pc;
    bool verbose;

    /* Parameters for non-generic plugins.  */
    bool is_generic;
    const TranslationBlock *tb;

    /* Some private state. */
    bool _in_gen_tpi_helper;
    bool _active;
    uint64_t _current_pc;
    const TranslationBlock *_current_tb;
    TCGArg *_tb_info;
    TCGArg *_tb_data1;
    TCGArg *_tb_data2;

    /* Plugin's callbacks.  */
    void *data;
    tpi_cpus_stopped_t cpus_stopped;
    tpi_before_gen_tb_t before_gen_tb;
    tpi_after_gen_tb_t  after_gen_tb;

    tpi_before_exec_tb_invalidate_opt_t before_exec_tb_invalidate_opt;  // hjx  
    tpi_before_exec_tb_t before_exec_tb;  //situ
    tpi_after_exec_tb_t after_exec_tb;    //situ

    tpi_pre_tb_helper_code_t pre_tb_helper_code;
    tpi_pre_tb_helper_data_t pre_tb_helper_data;
    tpi_after_gen_opc_t after_gen_opc;

    tpi_before_decode_first_instr_t before_decode_first_instr;
    tpi_after_decode_last_instr_t after_decode_last_instr;
    tpi_before_decode_instr_t before_decode_instr;

    /* Parameters callbacks */
    tpi_check_param_bool_t check_param_bool;
    tpi_check_param_int_t check_param_int;
    tpi_check_param_uint_t check_param_uint;
    tpi_check_param_string_t check_param_string;
    tpi_check_param_double_t check_param_double;
    tpi_get_param_bool_t get_param_bool;
    tpi_get_param_int_t get_param_int;
    tpi_get_param_uint_t get_param_uint;
    tpi_get_param_string_t get_param_string;
    tpi_get_param_double_t get_param_double;

    /* Active callback */
    tpi_active_changed_t active_changed;

    /* Parameters */
    GTree *parameters; /* string -> TPIParam */
};

#define TPI_INIT_VERSION(tpi) do {                                     \
        (tpi)->version = TPI_VERSION;                                   \
        (tpi)->guest   = TARGET_NAME;                                   \
        (tpi)->mode    = EMULATION_MODE;                                \
        (tpi)->sizeof_CPUState = sizeof(CPUState);                      \
        (tpi)->sizeof_TranslationBlock = sizeof(TranslationBlock);      \
        (tpi)->sizeof_TCGContext = sizeof(TCGContext);                  \
    } while (0)

#define TPI_INIT_VERSION_GENERIC(tpi) do {                             \
        (tpi)->version = TPI_VERSION;                                   \
        (tpi)->guest   = "any";                                         \
        (tpi)->mode    = "any";                                         \
        (tpi)->sizeof_CPUState = 0;                                     \
        (tpi)->sizeof_TranslationBlock = 0;                             \
        (tpi)->sizeof_TCGContext = sizeof(TCGContext);                  \
    } while (0)

/* Macros for declaration of plugin functions callable from target buffer.
   The declared function can then be called with tcg_gen_callN().
   For instance:
   void tpi_init(TCGPluginInterface *tpi) {
     TPI_INIT_VERSION_GENERIC(tpi);
     TPI_DECL_FUNC_2(tpi, myfunction, i64, i64, i32);
     ...
   }
   void after_gen_opc(TCGPluginInterface *tpi,...) {
     ...
     tcg_gen_callN(tpi->tcg_ctx, myfunction, GET_TCGV_I64(tcgv_ret), 2, args);
     ...
   }
 */

#define TPI_DECL_FUNC_0(tpi, NAME, ret) \
    TPI_DECL_FUNC_FLAGS_0(tpi, NAME, 0, ret)
#define TPI_DECL_FUNC_FLAGS_0(tpi, NAME, FLAGS, ret) do {                \
        static const TCGHelperInfo _info =                               \
            { .func = NAME, .name = #NAME, .flags = FLAGS,               \
              .sizemask = dh_sizemask(ret, 0) };                         \
        tcg_define_helper(&_info);                                       \
    } while (0)

#define TPI_DECL_FUNC_1(tpi, NAME, ret, t1)             \
    TPI_DECL_FUNC_FLAGS_1(tpi, NAME, 0, ret, t1)
#define TPI_DECL_FUNC_FLAGS_1(tpi, NAME, FLAGS, ret, t1) do {            \
        static const TCGHelperInfo _info =                               \
            { .func = NAME, .name = #NAME, .flags = FLAGS,               \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) };    \
        tcg_define_helper(&_info);                                       \
    } while (0)

#define TPI_DECL_FUNC_2(tpi, NAME, ret, t1, t2)         \
    TPI_DECL_FUNC_FLAGS_2(tpi, NAME, 0, ret, t1, t2)
#define TPI_DECL_FUNC_FLAGS_2(tpi, NAME, FLAGS, ret, t1, t2) do {        \
        static const TCGHelperInfo _info =                               \
            { .func = NAME, .name = #NAME, .flags = FLAGS,               \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)       \
              | dh_sizemask(t2, 2) };                                    \
        tcg_define_helper(&_info);                                       \
    } while (0)

#define TPI_DECL_FUNC_3(tpi, NAME, ret, t1, t2, t3) \
    TPI_DECL_FUNC_FLAGS_3(tpi, NAME, 0, ret, t1, t2, t3)
#define TPI_DECL_FUNC_FLAGS_3(tpi, NAME, FLAGS, ret, t1, t2, t3) do {    \
        static const TCGHelperInfo _info =                               \
            { .func = NAME, .name = #NAME, .flags = FLAGS,               \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)       \
              | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) };               \
        tcg_define_helper(&_info);                                       \
    } while (0)

#define TPI_DECL_FUNC_4(tpi, NAME, ret, t1, t2, t3, t4)                 \
    TPI_DECL_FUNC_FLAGS_4(tpi, NAME, 0, ret, t1, t2, t3, t4)
#define TPI_DECL_FUNC_FLAGS_4(tpi, NAME, FLAGS, ret, t1, t2, t3, t4) do {       \
        static const TCGHelperInfo _info =                                      \
            { .func = NAME, .name = #NAME, .flags = FLAGS,                      \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)              \
              | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) }; \
        tcg_define_helper(&_info);                                              \
    } while (0)

#define TPI_DECL_FUNC_5(tpi, NAME, ret, t1, t2, t3, t4, t5)             \
    TPI_DECL_FUNC_FLAGS_5(tpi, NAME, 0, ret, t1, t2, t3, t4, t5)
#define TPI_DECL_FUNC_FLAGS_5(tpi, NAME, FLAGS, ret, t1, t2, t3, t4, t5) do { \
        static const TCGHelperInfo _info =                                    \
            { .func = NAME, .name = #NAME, .flags = FLAGS,                    \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)            \
              | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4)  \
              | dh_sizemask(t5, 5) };                                         \
        tcg_define_helper(&_info);                                            \
    } while (0)


typedef void (*tpi_init_t)(TCGPluginInterface *tpi);
void tpi_init(TCGPluginInterface *tpi);

/*
 * Utility functions provided in addition to
 * QEMU interfaces callable from plugin execution time
 * or translation time helpers.
 */


/*
 * Global plugin interface accessors.
 */
static inline FILE *tpi_output(const TCGPluginInterface *tpi);

/*
 * Translation block accesors
 * Not static so plugins do not depend on definition of TranslationBlock.
 */
extern uint64_t tpi_tb_address(const TranslationBlock *tb);
extern uint32_t tpi_tb_size(const TranslationBlock *tb);
extern uint32_t tpi_tb_icount(const TranslationBlock *tb);

/*
 * Thread related identifiers.
 * Note that at translation time, these return the
 * translation thread ids which may be different from the
 * actual execution threads.
 */
static inline uint32_t tpi_thread_pid(const TCGPluginInterface *tpi);
static inline uint32_t tpi_thread_tid(const TCGPluginInterface *tpi);
static inline uint64_t tpi_thread_self(const TCGPluginInterface *tpi);

/*
 * QEMU CPUState and CPUArchState accessors.
 * Note that at translation time, these return the
 * translation CPU state which may be different from the
 * actual execution CPU state.
 */
static inline CPUState *tpi_current_cpu(const TCGPluginInterface *tpi);
static inline CPUArchState *tpi_current_cpu_arch(const TCGPluginInterface *tpi);
static inline uint32_t tpi_current_cpu_index(const TCGPluginInterface *tpi);
static inline uint32_t tpi_nb_cpus(const TCGPluginInterface *tpi);

/*
 * Execution lock functions.
 * Should be used for atomic regions executed from plugin
 * helpers such as printfs to tpi_output().
 * This lock is non recursive and will generate an
 * abort on relock condition.
 */
extern void tpi_exec_lock(const TCGPluginInterface *tpi);
extern void tpi_exec_unlock(const TCGPluginInterface *tpi);

/*
 * Activate or deactivate a plugin.
 * Flush translation cache on all cpus.
 */
extern void tpi_set_active(TCGPluginInterface *tpi, bool active);

/*
 * Find plugin from name.
 * @name string must be found in name field of plugin.
 * If name is NULL, find plugin with @id.
 * First occurence is returned.
 */
extern TCGPluginInterface *tpi_find_plugin(const char *name, uint32_t id);

/*
 * Are we currently executing a gen_tpi_helper callback because while another
 * plugins has a gen_tpi_helper callback on the stack?
 * Useful for avoiding interference between plugins.
 * For example, if you are executing a after_gen_opc callback and this
 * function returns true, the current QEMU opcode was generated by another
 * plugin.
 */
extern bool tpi_in_other_gen_tpi_helper(void);

/*
 * Declare parameters functions.
 */
extern void tpi_declare_param_bool(const TCGPluginInterface *tpi,
                                   const char *name, bool *value_ptr,
                                   bool default_value, const char *description);
extern void tpi_declare_param_uint(const TCGPluginInterface *tpi,
                                   const char *name, uint64_t *value_ptr,
                                   uint64_t default_value,
                                   const char *description);
extern void tpi_declare_param_int(const TCGPluginInterface *tpi,
                                  const char *name, int64_t *value_ptr,
                                  int64_t default_value,
                                  const char *description);
extern void tpi_declare_param_string(const TCGPluginInterface *tpi,
                                     const char *name, char **value_ptr,
                                     const char *default_value,
                                     const char *description);
extern void tpi_declare_param_double(const TCGPluginInterface *tpi,
                                     const char *name, double *value_ptr,
                                     double default_value,
                                     const char *description);

/*
 * Parameters set/get functions.
 * Set uses check_param callback if available.
 * Get uses get_param callback if available.
 */
extern bool tpi_set_param_bool(const TCGPluginInterface *tpi, const char *name,
                               bool value, char **error);
extern bool tpi_set_param_uint(const TCGPluginInterface *tpi, const char *name,
                               uint64_t value, char **error);
extern bool tpi_set_param_int(const TCGPluginInterface *tpi, const char *name,
                              int64_t value, char **error);
extern bool tpi_set_param_string(const TCGPluginInterface *tpi,
                                 const char *name, const char *value,
                                 char **error);
extern bool tpi_set_param_double(const TCGPluginInterface *tpi,
                                 const char *name, double value,
                                 char **error);
extern bool tpi_get_param_bool(const TCGPluginInterface *tpi, const char *name,
                               bool *value);
extern bool tpi_get_param_uint(const TCGPluginInterface *tpi, const char *name,
                               uint64_t *value);
extern bool tpi_get_param_int(const TCGPluginInterface *tpi, const char *name,
                              int64_t *value);
extern bool tpi_get_param_string(const TCGPluginInterface *tpi,
                                 const char *name,
                                 char **value);
extern bool tpi_get_param_double(const TCGPluginInterface *tpi,
                                 const char *name, double *value);

/*
 * parse value_str and set param with the result.
 */
extern bool tpi_set_param_from_string(const TCGPluginInterface *tpi,
                                      const char *param_name,
                                      const char *value_str, char **error);

/*
 * Guest to host address and loads.
 */
static inline uint64_t tpi_guest_ptr(const TCGPluginInterface *tpi,
                                     uint64_t guest_address);
static inline uint64_t tpi_guest_load64(const TCGPluginInterface *tpi,
                                        uint64_t guest_address);
static inline uint32_t tpi_guest_load32(const TCGPluginInterface *tpi,
                                        uint64_t guest_address);

#include "tcg-plugin.inc.c"

#else /* CONFIG_TCG_PLUGIN */
#   define tcg_plugin_enabled() false
#   define tcg_plugin_load(dso)
#   define tcg_plugin_initialize_all()
#   define tcg_plugin_cpus_stopped()
#   define tcg_plugin_before_gen_tb(tb)
#   define tcg_plugin_after_gen_tb(tb)
#   define tcg_plugin_before_exec_tb_invalidate_opt(tb) 0  // hjx, refer to panda-plugin
#   define tcg_plugin_before_exec_tb(tb)  //situ
#   define tcg_plugin_after_exec_tb(tb)   //situ
#   define tcg_plugin_before_decode_first_instr(tb)
#   define tcg_plugin_after_decode_last_instr(tb)
#   define tcg_plugin_before_decode_instr(pc)
#   define tcg_plugin_after_gen_opc(tcg_opcode, nb_args)
#   define tcg_plugin_get_filename() "<unknown>"
#endif /* !CONFIG_TCG_PLUGIN */


#endif /* TCG_PLUGIN_H */
