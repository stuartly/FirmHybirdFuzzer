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

#include <stdbool.h> /* bool, true, false, */
#include <assert.h>  /* assert(3), */
#include <dlfcn.h>   /* dlopen(3), dlsym(3), */
#include <unistd.h>  /* access(2), STDERR_FILENO, getpid(2), */
#include <fcntl.h>   /* open(2), */
#include <stdlib.h>  /* getenv(3), mkstemp(3), */
#include <string.h>  /* strlen(3), strerror(3), */
#include <stdio.h>   /* *printf(3), memset(3), */
#include <pthread.h> /* pthread_*, */
#include <stdint.h>  /* int*_t types, */
#include <sys/sendfile.h> /* sendfile(2), */
#include <execinfo.h>     /* backtrace(3), */
#include <libgen.h>  /* dirname(3), */
#include <stdarg.h>  /* va_arg(3) */
#include <inttypes.h>
#include <unistd.h>  /* stat(2) */

#include "tcg.h"
#include "tcg-op.h"
#include "tcg-plugin.h"
#include "exec/exec-all.h"   /* TranslationBlock */
#include "qom/cpu.h"         /* CPUState */
#include "sysemu/sysemu.h"   /* max_cpus */
#include "qemu/log.h"        /* qemu_set_log() */

/* glib must be included after osdep.h (which we include transitively via tcg.h) */
#include <glib.h>    /* glib2 objects/functions,*/

/* Definition of private externals used in tcg-plugin.inc.c. */
__thread uint32_t _tpi_thread_tid;

/* number of gen_tpi_helper callback currently live on the stack */
static __thread unsigned _gen_tpi_helper_depth;

/* Singleton plugins global state. */
static struct {

    /* Global configuration. */
    FILE *output;
    uint64_t low_pc;
    uint64_t high_pc;
    bool verbose;
    /* whether loading a plugin multiple times is allowed. On by default. */
    bool multi_load;

    /* Ensure resources used by *_helper_code are protected from
       concurrent access when mutex_protected is true.  */
    bool mutex_protected;
    pthread_mutex_t helper_mutex;

    /* User global plugin helpers execution mutex. */
    pthread_mutex_t user_mutex;

    /* Actual list of plugins. */
    GList *tpi_list;
} g_plugins_state;

static void TPIParam_ctor(TPIParam *p, const char *name, void *value_ptr,
                          enum TPI_PARAM_TYPE type, const char *description)
{
    p->name = g_strdup(name);
    p->type = type;
    p->value_ptr = value_ptr;
    p->description = g_strdup(description);
}

static void TPIParam_dtor(TPIParam *p)
{
    g_free(p->name);
    g_free(p->description);
}

static int g_tree_compare_string_keys(const void *a, const void *b, void *data)
{
    (void)data;
    return strcmp((const char *)a, (const char *)b);
}

static void g_tree_delete_TPIParam_value(void *data)
{
    TPIParam *p = (TPIParam *)data;
    TPIParam_dtor(p);
    g_free(p);
}

static TPIParam *get_parameter_pointer(const TCGPluginInterface *tpi,
                                       const char *name)
{
    return (TPIParam *)g_tree_lookup(tpi->parameters, name);
}

static const char *param_type_to_string(enum TPI_PARAM_TYPE type)
{
    switch (type) {
    case TPI_PARAM_TYPE_BOOL:
        return "bool";
        break;
    case TPI_PARAM_TYPE_INT:
        return "int";
        break;
    case TPI_PARAM_TYPE_UINT:
        return "uint";
        break;
    case TPI_PARAM_TYPE_STRING:
        return "string";
        break;
    case TPI_PARAM_TYPE_DOUBLE:
        return "double";
        break;
    }

    assert(false);
    return "";
}

TCGPluginInterface *tpi_find_plugin(const char *name, uint32_t id)
{
    GList *l;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (name) {
            if (strstr(tpi->name, name) != NULL) {
                return tpi;
            }
        } else {
            if (tpi->id == id) {
                return tpi;
            }
        }
    }

    return NULL;
}


bool tpi_in_other_gen_tpi_helper(void)
{
    return _gen_tpi_helper_depth > 1;
}


static char *param_value_to_string(const TCGPluginInterface *tpi,
                                   const char *name,
                                   enum TPI_PARAM_TYPE type)
{
    GString *res = g_string_new(NULL);
    bool has_result = false;

    switch (type) {
    case TPI_PARAM_TYPE_BOOL: {
        bool value = false;
        has_result = tpi_get_param_bool(tpi, name, &value);
        g_string_append_printf(res, "%s", value ? "true" : "false");
    } break;
    case TPI_PARAM_TYPE_INT: {
        int64_t value = 0;
        has_result = tpi_get_param_int(tpi, name, &value);
        g_string_append_printf(res, "%" PRId64, value);
    } break;
    case TPI_PARAM_TYPE_UINT: {
        uint64_t value = 0;
        has_result = tpi_get_param_uint(tpi, name, &value);
        g_string_append_printf(res, "%" PRIu64, value);
    } break;
    case TPI_PARAM_TYPE_STRING: {
        char *value = NULL;
        has_result = tpi_get_param_string(tpi, name, &value);
        g_string_append_printf(res, "\"%s\"", value);
        g_free(value);
    } break;
    case TPI_PARAM_TYPE_DOUBLE: {
        double value = 0;
        has_result = tpi_get_param_double(tpi, name, &value);
        g_string_append_printf(res, "%lf", value);
    } break;
    }

    char *result = g_string_free(res, false);
    if (has_result) {
        return result;
    }

    g_free(result);
    return NULL;
}

void tpi_set_active(TCGPluginInterface *tpi, bool active)
{
    if (tpi->_active == active) {
        return;
    }

    tpi->_active = active;

    /* flush translation cache on every cpu */
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        tb_flush(cpu);
    }

    if (tpi->active_changed) {
        tpi->active_changed(active);
    }
}

static bool command_enable_plugin(TCGPluginInterface *tpi,
                                  char **answer)
{
    tpi_set_active(tpi, true);
    return true;
}

static bool command_disable_plugin(TCGPluginInterface *tpi,
                                   char **answer)
{
    tpi_set_active(tpi, false);
    return true;
}

static int foreach_parameters_tree_get_parameters(void *key, void *value,
                                                  void *data)
{
    const TPIParam *param = (const TPIParam *)value;
    void **data_array = (void **)data;
    GString *res = (GString *)(data_array[0]);
    const TCGPluginInterface *tpi = (const TCGPluginInterface *)(data_array[1]);
    bool first = (res->len == 1); /* "[" */

    if (!first) {
        g_string_append(res, ",");
    }
    g_string_append_printf(res, "\"%s\": ", param->name);
    g_string_append(res, "{");
    g_string_append_printf(res, "\"description\": \"%s\", ",
                           param->description);
    g_string_append_printf(res, "\"type\": \"%s\", ",
                           param_type_to_string(param->type));
    char *param_value = param_value_to_string(tpi, param->name, param->type);
    g_string_append_printf(res, "\"value\": %s", param_value);
    g_free(param_value);
    g_string_append(res, "}\n");

    return 0;
}

static bool command_get_parameters(const TCGPluginInterface *tpi,
                                   char **answer)
{
    GString *res = g_string_new(NULL);

    void *data[] = {res, (void *)tpi};

    g_string_append(res, "{");
    g_tree_foreach(tpi->parameters, &foreach_parameters_tree_get_parameters,
                   data);
    g_string_append(res, "}");

    *answer = g_string_free(res, false);
    return true;
}

static bool command_set_parameter(const TCGPluginInterface *tpi, char **answer,
                                  const char *param_name, const char *value_str)
{
    TPIParam *p = get_parameter_pointer(tpi, param_name);
    if (!p) {
        *answer = g_strdup("parameter not found");
        return false;
    }

    bool bad_format = false;
    bool accepted_value = false;

    switch (p->type) {
    case TPI_PARAM_TYPE_BOOL: {
        bool value = false;
        if (strcmp(value_str, "true") == 0 || strcmp(value_str, "1") == 0) {
            value = true;
        } else if (strcmp(value_str, "false") == 0 ||
                   strcmp(value_str, "0") == 0) {
            value = false;
        } else {
            bad_format = true;
            goto end;
        }
        accepted_value = tpi_set_param_bool(tpi, param_name, value, answer);
    } break;
    case TPI_PARAM_TYPE_INT: {
        int64_t value = 0;
        if (sscanf(value_str, "%" SCNd64, &value) != 1) {
            bad_format = true;
            goto end;
        }
        accepted_value = tpi_set_param_int(tpi, param_name, value, answer);
    } break;
    case TPI_PARAM_TYPE_UINT: {
        uint64_t value = 0;
        if (sscanf(value_str, "%" SCNu64, &value) != 1) {
            bad_format = true;
            goto end;
        }
        accepted_value = tpi_set_param_uint(tpi, param_name, value, answer);
    } break;
    case TPI_PARAM_TYPE_STRING:
        accepted_value =
            tpi_set_param_string(tpi, param_name, value_str, answer);
        break;
    case TPI_PARAM_TYPE_DOUBLE: {
        double value = 0;
        if (sscanf(value_str, "%lf", &value) != 1) {
            bad_format = true;
            goto end;
        }
        accepted_value = tpi_set_param_double(tpi, param_name, value, answer);
    } break;
    }

end:
    if (bad_format) {
        *answer = g_strdup("bad format for parameter");
    }
    return accepted_value && !bad_format;
}

bool tpi_set_param_from_string(const TCGPluginInterface *tpi,
                               const char *param_name,
                               const char *value_str, char **error)
{
    assert(value_str);

    return command_set_parameter(tpi, error, param_name, value_str);
}

/* return list of plugins and their status */
static bool command_get_plugins(char **answer)
{
    GString *res = g_string_new(NULL);

    g_string_append(res, "[");

    bool first = true;

    {
        GList *l;
        for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
            const TCGPluginInterface *tpi = (const TCGPluginInterface *)l->data;
            if (!first) {
                g_string_append(res, ",");
            } else {
                first = false;
            }
            g_string_append_printf(res, "{\"name\": \"%s\","
                                        "\"id\": %d,"
                                        "\"active\": %s}",
                                          tpi->name,
                                          tpi->id,
                                          tpi->_active ? "true" : "false");
        }
    }

    g_string_append(res, "]");

    *answer = g_string_free(res, false);
    return true;
}

enum TPI_PLUGIN_COMMAND {
    TPI_PLUGIN_COMMAND_GET_PLUGINS,
    TPI_PLUGIN_COMMAND_GET_PARAMETERS,
    TPI_PLUGIN_COMMAND_SET_PARAMETER,
    TPI_PLUGIN_COMMAND_ENABLE_PLUGIN,
    TPI_PLUGIN_COMMAND_DISABLE_PLUGIN,
    TPI_PLUGIN_COMMAND_UNKNOWN
};

static enum TPI_PLUGIN_COMMAND string_to_plugin_command(const char *command)
{
    if (strcmp(command, "get-plugins") == 0) {
        return TPI_PLUGIN_COMMAND_GET_PLUGINS;
    } else if (strcmp(command, "get-parameters") == 0) {
        return TPI_PLUGIN_COMMAND_GET_PARAMETERS;
    } else if (strcmp(command, "set-parameter") == 0) {
        return TPI_PLUGIN_COMMAND_SET_PARAMETER;
    } else if (strcmp(command, "enable-plugin") == 0) {
        return TPI_PLUGIN_COMMAND_ENABLE_PLUGIN;
    } else if (strcmp(command, "disable-plugin") == 0) {
        return TPI_PLUGIN_COMMAND_DISABLE_PLUGIN;
    } else {
        return TPI_PLUGIN_COMMAND_UNKNOWN;
    }
}

static bool handle_command(enum TPI_PLUGIN_COMMAND command_type, char **answer,
                           GList *args, unsigned int nb_args)
{
    /* check if command needs a plugin name */
    TCGPluginInterface *tpi = NULL;
    switch (command_type) {
    case TPI_PLUGIN_COMMAND_GET_PLUGINS:
    case TPI_PLUGIN_COMMAND_UNKNOWN:
        break;
    case TPI_PLUGIN_COMMAND_SET_PARAMETER:
    case TPI_PLUGIN_COMMAND_GET_PARAMETERS:
    case TPI_PLUGIN_COMMAND_ENABLE_PLUGIN:
    case TPI_PLUGIN_COMMAND_DISABLE_PLUGIN:
        if (nb_args < 1) {
            *answer = g_strdup("expect plugin_name as first arg");
            return false;
        }
        const char *plugin_name = (const char *)g_list_nth_data(args, 0);
        uint32_t plugin_id = -1;

        bool name_is_id = true;
        {
            const char *it;
            for (it = plugin_name; it && *it; ++it) {
                if (!isdigit(*it)) {
                    name_is_id = false;
                    break;
                }
            }
        }

        if (name_is_id) {
            plugin_id = atoi(plugin_name);
            plugin_name = NULL;
        }

        tpi = tpi_find_plugin(plugin_name, plugin_id);
        if (!tpi) {
            *answer = g_strdup("plugin not found");
            return false;
        }
    }

    /* treat command */
    switch (command_type) {
    case TPI_PLUGIN_COMMAND_GET_PLUGINS:
        if (nb_args != 0) {
            *answer = g_strdup("expect 0 args");
            return false;
        }
        return command_get_plugins(answer);
        break;
    case TPI_PLUGIN_COMMAND_GET_PARAMETERS: {
        if (nb_args != 1) {
            *answer = g_strdup("expect 1 arg, usage: plugin_name");
            return false;
        }
        return command_get_parameters(tpi, answer);
    } break;
    case TPI_PLUGIN_COMMAND_SET_PARAMETER: {
        if (nb_args != 3) {
            *answer =
                g_strdup("expect 3 arg, usage: plugin_name param_name value");
            return false;
        }
        const char *param_name = (const char *)g_list_nth_data(args, 1);
        const char *value = (const char *)g_list_nth_data(args, 2);
        return command_set_parameter(tpi, answer, param_name, value);
    } break;
    case TPI_PLUGIN_COMMAND_ENABLE_PLUGIN: {
        if (nb_args != 1) {
            *answer = g_strdup("expect 1 arg, usage: plugin_name");
            return false;
        }
        return command_enable_plugin(tpi, answer);
    } break;
    case TPI_PLUGIN_COMMAND_DISABLE_PLUGIN: {
        if (nb_args != 1) {
            *answer = g_strdup("expect 1 arg, usage: plugin_name");
            return false;
        }
        return command_disable_plugin(tpi, answer);
    } break;
    case TPI_PLUGIN_COMMAND_UNKNOWN:
        *answer = g_strdup("unknown command");
        return false;
        break;
    }

        return true;
}

bool tcg_plugin_treat_command(const char *command, char **answer)
{
    char *command_buffer = g_strdup(command);
    bool success = false;

    GList *command_elem = NULL;

    /* split command in list of args */
    const char *delim = " ";
    char *save_ptr = NULL;
    char *token = strtok_r(command_buffer, delim, &save_ptr);
    while (token != NULL) {
        command_elem = g_list_append(command_elem, token);
        token = strtok_r(NULL, delim, &save_ptr);
    }

    if (command_elem == NULL) {
        *answer = g_strdup("no command given");
        goto end;
    }

    const char *command_name = (const char *)g_list_nth_data(command_elem, 0);
    GList *args = g_list_nth(command_elem, 1);
    unsigned int nb_args = g_list_length(args);
    enum TPI_PLUGIN_COMMAND command_type =
        string_to_plugin_command(command_name);
    success = handle_command(command_type, answer, args, nb_args);

end:
    free(command_buffer);
    g_list_free(command_elem);
    return success;
}

void tcg_plugin_load(const char *name)
{
    TCGPluginInterface *tpi;

    assert(name != NULL);

    static uint32_t unique_id;

    tpi = g_malloc0(sizeof(TCGPluginInterface));
    tpi->name = (char *)g_strdup(name);
    tpi->id = unique_id;
    g_plugins_state.tpi_list = g_list_append(g_plugins_state.tpi_list, tpi);

    ++unique_id;
}

/***
 * Check if wanted is in list of expected strings passed as NULL
 * terminated varargs list.
 * Ignores case.
 */
static bool stroneof_nocase(const char *wanted, ...)
{
    const char *expected;
    bool found = false;

    va_list ap;
    va_start(ap, wanted);
    while ((expected = va_arg(ap, const char *))) {
        if (g_ascii_strcasecmp(wanted, expected) == 0) {
            found = true;
        }
    }
    va_end(ap);

    return found;
}

/* Initialize global plugins state, unless already done. */
static void tcg_plugin_state_init(void)
{
    const char *tmp;

    if (g_plugins_state.output != NULL) {
        return;
    }

    /* No TB chain with plugins as we must have an up to date
     * env->current_tb for the plugin interface.
     */
    qemu_set_log(CPU_LOG_TB_NOCHAIN);

    /* Plugins output is, in order of priority:
     *
     * 1. the file $TPI_OUTPUT.$PID if the environment variable
     *    TPI_OUTPUT is defined.
     *
     * 2. a duplicate of the error stream.
     *
     * 3. the error stream itself.
     */
    if (getenv("TPI_OUTPUT")) {
        int no_pid = getenv("TPI_OUTPUT_NO_PID") != NULL;
        char path[PATH_MAX];
        if (no_pid) {
            snprintf(path, PATH_MAX, "%s", getenv("TPI_OUTPUT"));
        } else {
            snprintf(path, PATH_MAX, "%s.%d", getenv("TPI_OUTPUT"), getpid());
        }
        g_plugins_state.output = fopen(path, "w");
        if (!g_plugins_state.output) {
            fprintf(stderr, "plugin: warning: can't open TPI_OUTPUT "
                    "(falling back to stderr) at %s: %s\n",
                    path, strerror(errno));
        } else {
            if (!no_pid) {
                /* Create a convenient link to last opened output. */
                int status;
                unlink(getenv("TPI_OUTPUT"));
                status = symlink(path, getenv("TPI_OUTPUT"));
                if (status != 0) {
                    fprintf(stderr, "plugin: warning: can't create symlink "
                            "TPI_OUTPUT at %s: %s\n",
                            getenv("TPI_OUTPUT"), strerror(errno));
                }
            }
        }
    }
    if (!g_plugins_state.output) {
        g_plugins_state.output = fdopen(dup(fileno(stderr)), "a");
    }
    if (!g_plugins_state.output) {
        g_plugins_state.output = stderr;
    }
    assert(g_plugins_state.output != NULL);

    /* This is a compromise between buffered output and truncated
     * output when exiting through _exit(2) in user-mode.  */
    setlinebuf(g_plugins_state.output);

    g_plugins_state.low_pc = 0;
    g_plugins_state.high_pc = UINT64_MAX;

    if (getenv("TPI_SYMBOL_PC")) {
#if 0
        struct syminfo *syminfo =
            reverse_lookup_symbol(getenv("TPI_SYMBOL_PC"));
        if (!syminfo)  {
            fprintf(stderr,
                    "plugin: warning: symbol '%s' not found\n",
                    getenv("TPI_SYMBOL_PC"));
        } else {
            g_plugins_state.low_pc  = syminfo.disas_symtab.elfXX.st_value;
            g_plugins_state.high_pc = g_plugins_state.low_pc +
                syminfo.disas_symtab.elfXX.st_size;
        }
#else
        fprintf(stderr,
                "plugin: warning: TPI_SYMBOL_PC parameter not supported yet\n");
#endif
    }

    if (getenv("TPI_LOW_PC")) {
        g_plugins_state.low_pc = (uint64_t) strtoull(getenv("TPI_LOW_PC"), NULL, 0);
        if (!g_plugins_state.low_pc) {
            fprintf(stderr,
                    "plugin: warning: can't parse TPI_LOW_PC (fall back to 0)\n");
        }
    }

    if (getenv("TPI_HIGH_PC")) {
        g_plugins_state.high_pc = (uint64_t) strtoull(getenv("TPI_HIGH_PC"), NULL, 0);
        if (!g_plugins_state.high_pc) {
            fprintf(stderr,
                    "plugin: warning: can't parse TPI_HIGH_PC (fall back to UINT64_MAX)\n");
            g_plugins_state.high_pc = UINT64_MAX;
        }
    }

    g_plugins_state.verbose = getenv("TPI_VERBOSE") != NULL;

    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
        pthread_mutex_init(&g_plugins_state.user_mutex, &attr);

        g_plugins_state.mutex_protected = getenv("TPI_MUTEX_PROTECTED") != NULL;
        pthread_mutex_init(&g_plugins_state.helper_mutex, NULL);
    }

    tmp = getenv("TPI_MULTI_LOAD");

    const bool default_multi_load = false;

    if (tmp) {
        if (stroneof_nocase(tmp, "0", "NO", "N", "OFF" "false", NULL)) {
            g_plugins_state.multi_load = false;
        } else if (stroneof_nocase(tmp, "1", "YES", "Y", "ON", "true", NULL)) {
            g_plugins_state.multi_load = false;
        } else {
            fprintf(
                stderr,
                "plugin: error: invalid value '%s' for "
                "TPI_MULTI_LOAD, use '0' or '1'.\n", g_strescape(tmp, ""));

            exit(EXIT_FAILURE);
        }
    } else {
        g_plugins_state.multi_load = default_multi_load;
    }
}

/* Load the dynamic shared object "name" and call its function
 * "tpi_init()" to initialize itself.  Then, some sanity checks are
 * performed to ensure the dynamic shared object is compatible with
 * this instance of QEMU (guest CPU, emulation mode, ...).  */
static void tcg_plugin_tpi_init(TCGPluginInterface *tpi)
{
#if !defined(CONFIG_SOFTMMU)
    unsigned int max_cpus = 1;
#endif
    tpi_init_t tpi_init;
    char *path = NULL;
    void *handle = NULL;
    int plugin_fd = -1;
    int plugin_instance_fd = -1;
    char *plugin_instance_path = NULL;
    char *exec_dir;

    assert(tpi != NULL);
    assert(tpi->name != NULL);

    tcg_plugin_state_init();

    exec_dir = qemu_get_exec_dir();

    /* Check if "name" refers to an installed/compiled plugin (short form).  */
    if (tpi->name[0] != '.' && strchr(tpi->name, '/') == NULL &&
        exec_dir != NULL && exec_dir[0] == '/') {
        char *prefix;
        const char *format;
        size_t size;

        /* look for installed plugin */
        prefix = dirname(exec_dir);
        format = "%s/libexec/" TARGET_NAME "/" EMULATION_MODE "/tcg-plugin-%s.so";
        size = strlen(format) + strlen(prefix) - strlen("%s") +
            strlen(tpi->name) - strlen("%s") + 1;
        path = g_malloc0(size * sizeof(char));
        snprintf(path, size, format, prefix, tpi->name);
        g_free(exec_dir);

        struct stat buf;
        if (stat(path, &buf) != 0) {
            /* look for compiled plugin */
            char *exe_path = NULL;
#ifdef __linux__
            exe_path = realpath("/proc/self/exe", NULL);
#endif
            assert(exe_path);

            prefix = dirname(exe_path);
            format = "%s/tcg-plugin-%s.so";
            size = strlen(format) + strlen(prefix) +
                   strlen(tpi->name) - 2 * strlen("%s") + 1;
            snprintf(path, size, format, prefix, tpi->name);

            free(exe_path);
        }

        if (stat(path, &buf) != 0) /* plugin was not found installed/compiled */
        {
            g_free(path);
            path = NULL;
        }
    }

    if (!path) {
        path = g_strdup(tpi->name);
    }
    tpi->path_name = path;

    /*
     * Make a copy of the plugin file in order to allow multiple loads
     * of the same plugin.
     */
    if (g_plugins_state.multi_load) {
        struct stat plugin_info = {0};
        ssize_t count, size;
        int status;

        plugin_fd = open(path, O_RDONLY);
        if (plugin_fd < 0) {
            fprintf(stderr, "plugin: error: can't open plugin at %s: %s\n",
                    path, strerror(errno));
            goto error;
        }

        plugin_instance_path = g_strdup("/tmp/qemu-plugin-XXXXXX");

        plugin_instance_fd = mkstemp(plugin_instance_path);
        if (plugin_instance_fd < 0) {
            fprintf(stderr, "plugin: error: can't create temporary file: %s\n",
                    strerror(errno));
            goto error;
        }

        status = fstat(plugin_fd, &plugin_info);
        if (status != 0) {
            fprintf(stderr, "plugin: error: can't stat file at %s: %s\n", path,
                    strerror(errno));
            goto error;
        }

        size = plugin_info.st_size;
        count = 0;
        while (count < size) {
            size -= count;
            count = sendfile(plugin_instance_fd, plugin_fd, NULL, size);
            if (count < 0) {
                fprintf(stderr, "plugin: error: can't copy plugin file at %s: %s\n",
                        path, strerror(errno));
                goto error;
            }
        }
    } else {
        plugin_instance_path = g_strdup(path);
    }
    tpi->instance_path_name = plugin_instance_path;

    /*
     * Load the dynamic shared object and retreive its symbol
     * "tpi_init".
     */
#ifdef NEED_GDB_BACKTRACE_PLUGIN
    handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
#else
    handle = dlopen(plugin_instance_path, RTLD_NOW | RTLD_GLOBAL);
#endif
    if (!handle) {
        fprintf(stderr, "plugin: error: can't load plugin at %s  %s\n",
                plugin_instance_path, dlerror());
        goto error;
    }
    tpi->instance_handle = handle;

    tpi_init = dlsym(handle, "tpi_init");
    if (!tpi_init) {
        fprintf(stderr, "plugin: error: can't resolve 'tpi_init' function in plugin at %s: %s\n",
                path, dlerror());
        goto error;
    }

    /*
     * Fill the interface with information that may be useful to the
     * plugin initialization.
     */

    TPI_INIT_VERSION(tpi);

    tpi->nb_cpus = max_cpus;
    assert(tpi->nb_cpus >= 0);

    tpi->tcg_ctx = tcg_ctx;
    assert(tpi->tcg_ctx != NULL);

    tpi->output = fdopen(dup(fileno(g_plugins_state.output)), "a");
    setlinebuf(tpi->output);

    tpi->low_pc = g_plugins_state.low_pc;
    tpi->high_pc = g_plugins_state.high_pc;

    tpi->parameters = g_tree_new_full(g_tree_compare_string_keys, NULL, NULL,
                                      g_tree_delete_TPIParam_value);

    /*
     * Tell the plugin to initialize itself.
     */

    tpi_init(tpi);

    /* activate plugin by default */
    tpi_set_active(tpi, true);

    /*
     * Perform some sanity checks to ensure this TCG plugin is
     * compatible with this instance of QEMU (guest CPU, emulation
     * mode, ...)
     */

    if (!tpi->version) {
        fprintf(stderr, "plugin: error: initialization has failed\n");
        goto error;
    }

    if (tpi->version != TPI_VERSION) {
        fprintf(stderr, "plugin: error: incompatible plugin interface (%d != %d)\n",
                tpi->version, TPI_VERSION);
        goto error;
    }

    if (tpi->sizeof_CPUState != 0
        && tpi->sizeof_CPUState != sizeof(CPUState)) {
        fprintf(stderr, "plugin: error: incompatible CPUState size "
                "(%zu != %zu)\n", tpi->sizeof_CPUState, sizeof(CPUState));
        goto error;
    }

    if (tpi->sizeof_TranslationBlock != 0
        && tpi->sizeof_TranslationBlock != sizeof(TranslationBlock)) {
        fprintf(stderr, "plugin: error: incompatible TranslationBlock size "
                "(%zu != %zu)\n", tpi->sizeof_TranslationBlock,
                sizeof(TranslationBlock));
        goto error;
    }

    if (tpi->sizeof_TCGContext != sizeof(TCGContext)) {
        fprintf(stderr, "plugin: error: incompatible TCGContext size "
                "(%zu != %zu)\n", tpi->sizeof_TCGContext, sizeof(TCGContext));
        goto error;
    }

    if (strcmp(tpi->guest, TARGET_NAME) != 0
        && strcmp(tpi->guest, "any") != 0) {
        fprintf(stderr, "plugin: warning: incompatible guest CPU "
                "(%s != %s)\n", tpi->guest, TARGET_NAME);
    }

    if (strcmp(tpi->mode, EMULATION_MODE) != 0
        && strcmp(tpi->mode, "any") != 0) {
        fprintf(stderr, "plugin: warning: incompatible emulation mode "
                "(%s != %s)\n", tpi->mode, EMULATION_MODE);
    }

    tpi->is_generic = strcmp(tpi->guest, "any") == 0 &&
                      strcmp(tpi->mode, "any") == 0;

    if (g_plugins_state.verbose) {
        tpi->verbose = true;
        fprintf(tpi->output, "plugin: info: name = %s\n", tpi->name);
        fprintf(tpi->output, "plugin: info: version = %d\n", tpi->version);
        fprintf(tpi->output, "plugin: info: guest = %s\n", tpi->guest);
        fprintf(tpi->output, "plugin: info: mode = %s\n", tpi->mode);
        fprintf(tpi->output, "plugin: info: sizeof(CPUState) = %zu\n", tpi->sizeof_CPUState);
        fprintf(tpi->output, "plugin: info: sizeof(TranslationBlock) = %zu\n", tpi->sizeof_TranslationBlock);
        fprintf(tpi->output, "plugin: info: output fd = %d\n", fileno(tpi->output));
        fprintf(tpi->output, "plugin: info: low pc = 0x%016" PRIx64 "\n", tpi->low_pc);
        fprintf(tpi->output, "plugin: info: high pc = 0x%016" PRIx64 "\n", tpi->high_pc);
        fprintf(tpi->output, "plugin: info: cpus_stopped callback = %p\n", tpi->cpus_stopped);
        fprintf(tpi->output, "plugin: info: before_gen_tb callback = %p\n", tpi->before_gen_tb);
        fprintf(tpi->output, "plugin: info: before_decode_first_instr callback = %p\n", tpi->before_decode_first_instr);
        fprintf(tpi->output, "plugin: info: after_decode_last_instr callback = %p\n", tpi->after_decode_last_instr);
        fprintf(tpi->output, "plugin: info: before_decode_instr callback = %p\n", tpi->before_decode_instr);
        fprintf(tpi->output, "plugin: info: after_gen_tb callback = %p\n", tpi->after_gen_tb);
        fprintf(tpi->output, "plugin: info: before_exec_tb_invalidate_opt callback = %p\n", tpi->before_exec_tb_invalidate_opt);  // hjx
        fprintf(tpi->output, "plugin: info: before_exec_tb callback = %p\n", tpi->before_exec_tb);  //situ
        fprintf(tpi->output, "plugin: info: after_exec_tb callback = %p\n", tpi->after_exec_tb);    //situ
        fprintf(tpi->output, "plugin: info: after_gen_opc callback = %p\n", tpi->after_gen_opc);
        fprintf(tpi->output, "plugin: info: pre_tb_helper_code callback = %p\n", tpi->pre_tb_helper_code);
        fprintf(tpi->output, "plugin: info: pre_tb_helper_data callback = %p\n", tpi->pre_tb_helper_data);
        fprintf(tpi->output, "plugin: info: is%s generic\n", tpi->is_generic ? "" : " not");
    }

    close(plugin_fd);
    close(plugin_instance_fd);
    if (g_plugins_state.multi_load) {
        unlink(plugin_instance_path);
    }

    return;

error:
    g_free(path);
    g_free(plugin_instance_path);

    if (plugin_fd >= 0) {
        close(plugin_fd);
    }

    if (plugin_instance_fd >= 0) {
        close(plugin_instance_fd);
        if (g_plugins_state.multi_load) {
            unlink(plugin_instance_path);
        }
    }

    if (handle != NULL) {
        dlclose(handle);
    }

    memset(tpi, 0, sizeof(*tpi));

    exit(EXIT_FAILURE);

    return;
}

/* Initialize once the plugin interface an returns true on success.
   Must be called before any attempt to use the tpi interface as
   actual loading is defered until the plugin hooks are called.
 */
static bool tcg_plugin_initialize(TCGPluginInterface *tpi)
{
    assert(tpi != NULL);
    if (tpi->version > 0) {
        return 1;
    }
    if (tpi->version == -1) {
        return 0;
    }

    /* This is the first initialization, if failed, set version to -1. */
    tcg_plugin_tpi_init(tpi);
    if (tpi->version == 0) {
        tpi->version = -1;
    }

    return tpi->version > 0;
}

/* Wrapper to ensure only non-generic plugins can access non-generic data.  */
#define TPI_CALLBACK_NOT_GENERIC(tpi, callback, ...)       \
    do {                                                   \
        if (!tpi->is_generic) {                            \
            tpi->tb = tpi->_current_tb;                    \
        }                                                  \
        tpi->callback(tpi, ##__VA_ARGS__);                 \
        tpi->tb = NULL;                                    \
    } while (0)

static void tcg_plugin_tpi_before_gen_tb(TCGPluginInterface *tpi,
                                         TranslationBlock *tb)
{
    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;

    if (tpi->before_gen_tb) {
        TPI_CALLBACK_NOT_GENERIC(tpi, before_gen_tb);
    }

    /* Generate TCG opcodes to call helper_tcg_plugin_tb*().  */
    if (tpi->pre_tb_helper_code) {
        TCGv_i64 data1;
        TCGv_i64 data2;
        TCGv_i64 info;
        TCGv_i64 address;
        TCGv_i64 tpi_ptr;
        TCGv_i64 tb_ptr;
        static int iii;

        tpi_ptr = tcg_const_i64((uint64_t)tpi);
        tb_ptr = tcg_const_i64((uint64_t)tb);

        address = tcg_const_i64((uint64_t)tb->pc);

        /* Patched in tcg_plugin_after_gen_tb().  */
        info = tcg_const_i64(iii++);
        tpi->_tb_info = &tcg_last_op()->args[1];

        /* Patched in tcg_plugin_after_gen_tb().  */
        data1 = tcg_const_i64(0);
        tpi->_tb_data1 = &tcg_last_op()->args[1];

        /* Patched in tcg_plugin_after_gen_tb().  */
        data2 = tcg_const_i64(0);
        tpi->_tb_data2 = &tcg_last_op()->args[1];

        gen_helper_tcg_plugin_pre_tb(tpi_ptr, address, info, data1, data2, tb_ptr);

        tcg_temp_free_i64(data2);
        tcg_temp_free_i64(data1);
        tcg_temp_free_i64(info);
        tcg_temp_free_i64(address);
    }

    tpi->_in_gen_tpi_helper = false;
}

static void tcg_plugin_tpi_after_gen_tb(TCGPluginInterface *tpi,
                                        TranslationBlock *tb)
{
    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;

    if (tpi->pre_tb_helper_code) {
        /* Patch helper_tcg_plugin_tb*() parameters.  */
        ((TPIHelperInfo *)tpi->_tb_info)->cpu_index = tpi_current_cpu_index(tpi);
        ((TPIHelperInfo *)tpi->_tb_info)->size = tb->size;
#if TCG_TARGET_REG_BITS == 64
        ((TPIHelperInfo *)tpi->_tb_info)->icount = tb->icount;
#else
        /* i64 variables use 2 arguments on 32-bit host.  */
        *(tpi->_tb_info + 2) = tb->icount;
#endif

        /* Callback variables have to be initialized [when not used]
         * to ensure deterministic code generation, e.g. on some host
         * the opcode "movi_i64 tmp,$value" isn't encoded the same
         * whether $value fits into a given host instruction or
         * not.  */
        uint64_t data1 = 0;
        uint64_t data2 = 0;

        if (tpi->pre_tb_helper_data) {
            TPI_CALLBACK_NOT_GENERIC(tpi, pre_tb_helper_data,
                                     *(TPIHelperInfo *)tpi->_tb_info, tb->pc,
                                     &data1, &data2, tb);
        }

#if TCG_TARGET_REG_BITS == 64
        *(uint64_t *)tpi->_tb_data1 = data1;
        *(uint64_t *)tpi->_tb_data2 = data2;
#else
        /* i64 variables use 2 arguments on 32-bit host.  */
        *tpi->_tb_data1 = data1 & 0xFFFFFFFF;
        *(tpi->_tb_data1 + 2) = data1 >> 32;

        *tpi->_tb_data2 = data2 & 0xFFFFFFFF;
        *(tpi->_tb_data2 + 2) = data2 >> 32;
#endif
    }

    if (tpi->after_gen_tb) {
        TPI_CALLBACK_NOT_GENERIC(tpi, after_gen_tb);
    }

    tpi->_in_gen_tpi_helper = false;
}


static void tcg_plugin_tpi_before_exec_tb(TCGPluginInterface *tpi,
                                                     TranslationBlock *tb)
{
    assert(tb);

    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;
    tpi->tb = tb;

    if (tpi->before_exec_tb) {
        TPI_CALLBACK_NOT_GENERIC(tpi, before_exec_tb);
    }

    tpi->tb = NULL;
    tpi->_in_gen_tpi_helper = false;
}


static int tcg_plugin_tpi_before_exec_tb_invalidate_opt(TCGPluginInterface *tpi,
                                                     TranslationBlock *tb)
{
    assert(tb);

    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;
    tpi->tb = tb;

    int is_invalidate_opt = 0;
    if (tpi->before_exec_tb_invalidate_opt) {
        if (!tpi->is_generic) { 
            tpi->tb = tpi->_current_tb;
        }
        is_invalidate_opt = tpi->before_exec_tb_invalidate_opt(tpi);
        tpi->tb = NULL;    
    }

    tpi->tb = NULL;
    tpi->_in_gen_tpi_helper = false;

    return is_invalidate_opt;
}


static void tcg_plugin_tpi_after_exec_tb(TCGPluginInterface *tpi,
                                                     TranslationBlock *tb)
{
    assert(tb);

    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;
    tpi->tb = tb;

    if (tpi->after_exec_tb) {
        TPI_CALLBACK_NOT_GENERIC(tpi, after_exec_tb);
    }

    tpi->tb = NULL;
    tpi->_in_gen_tpi_helper = false;
}

static void tcg_plugin_tpi_before_decode_first_instr(TCGPluginInterface *tpi,
                                                     TranslationBlock *tb)
{
    assert(tb);

    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;
    tpi->tb = tb;

    if (tpi->before_decode_first_instr) {
        tpi->before_decode_first_instr(tpi, tb);
    }

    tpi->tb = NULL;
    tpi->_in_gen_tpi_helper = false;
}


static void tcg_plugin_tpi_after_decode_last_instr(TCGPluginInterface *tpi,
                                                   TranslationBlock *tb)
{
    assert(tb);

    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;
    tpi->tb = tb;

    if (tpi->after_decode_last_instr) {
        tpi->after_decode_last_instr(tpi, tb);
    }

    tpi->tb = NULL;
    tpi->_in_gen_tpi_helper = false;
}




static void tcg_plugin_tpi_after_gen_opc(TCGPluginInterface *tpi,
                                         TCGOp *opcode, uint8_t nb_args)
{
    TPIOpCode tpi_opcode;

    /* Catch insn_start opcodes to get the current pc. */
    if (opcode->opc == INDEX_op_insn_start) {
#if TARGET_LONG_BITS <= TCG_TARGET_REG_BITS
        tpi->_current_pc = opcode->args[0];
#else
        tpi->_current_pc = deposit64(opcode->args[0], 32, 32, opcode->args[1]);
#endif
    }

    if (tpi->_current_pc < tpi->low_pc || tpi->_current_pc >= tpi->high_pc) {
        return;
    }

    if (tpi->_in_gen_tpi_helper) {
        return;
    }

    tpi->_in_gen_tpi_helper = true;

    nb_args = MIN(nb_args, TPI_MAX_OP_ARGS);

    tpi_opcode.pc   = tpi->_current_pc;
    tpi_opcode.cpu_index = tpi_current_cpu_index(tpi);
    tpi_opcode.nb_args = nb_args;

    tpi_opcode.operator = opcode->opc;
    tpi_opcode.opcode = opcode;
    tpi_opcode.opargs = opcode->args;

    if (tpi->after_gen_opc) {
        TPI_CALLBACK_NOT_GENERIC(tpi, after_gen_opc, &tpi_opcode);
    }

    tpi->_in_gen_tpi_helper = false;
}


/* TCG helper used to call pre_tb_helper_code() in a thread-safe
 * way.  */
void helper_tcg_plugin_pre_tb(uint64_t tpi_ptr,
                              uint64_t address, uint64_t info,
                              uint64_t data1, uint64_t data2,
                              uint64_t tb_ptr)
{
    int error;

    if (g_plugins_state.mutex_protected) {
        error = pthread_mutex_lock(&g_plugins_state.helper_mutex);
        if (error) {
            fprintf(stderr, "plugin: in call_pre_tb_helper_code(), "
                    "pthread_mutex_lock() has failed: %s\n",
                    strerror(error));
            goto end;
        }
    }

    TCGPluginInterface *tpi = (TCGPluginInterface *)(intptr_t)tpi_ptr;
    const TranslationBlock *tb = (TranslationBlock *)(intptr_t)tb_ptr;
    if (tcg_plugin_initialize(tpi)) {
        TPI_CALLBACK_NOT_GENERIC(tpi, pre_tb_helper_code,
                                 *(TPIHelperInfo *)&info,
                                 address, data1, data2, tb);
    }
end:
    if (g_plugins_state.mutex_protected) {
        pthread_mutex_unlock(&g_plugins_state.helper_mutex);
    }
}

#if !defined(CONFIG_USER_ONLY)
const char *tcg_plugin_get_filename(void)
{
    return "<system>";
}
#else
extern const char *exec_path;
const char *tcg_plugin_get_filename(void)
{
    return exec_path;
}
#endif

/* Return true if at least one plugin was requested.  */
bool tcg_plugin_enabled(void)
{
    return g_plugins_state.tpi_list != NULL;
}

/* Hook called before the Intermediate Code Generation (ICG).  */
void tcg_plugin_cpus_stopped(void)
{
    GList *l;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi) && tpi->cpus_stopped) {
            TPI_CALLBACK_NOT_GENERIC(tpi, cpus_stopped);
        }
    }
}

/* Hook called before the Intermediate Code Generation (ICG).  */
void tcg_plugin_before_gen_tb(TranslationBlock *tb)
{
    GList *l;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = tb->pc;
            tpi->_current_tb = tb;
        }
    }

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tcg_plugin_tpi_before_gen_tb(tpi, tb);
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}


/* Hook called after the Intermediate Code Generation (ICG).  */
void tcg_plugin_after_gen_tb(TranslationBlock *tb)
{
    GList *l;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tcg_plugin_tpi_after_gen_tb(tpi, tb);
        }
    }

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = 0;
            tpi->_current_tb = NULL;
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}


/* Hook called before tblock executed invalidate_opt.  */
int tcg_plugin_before_exec_tb_invalidate_opt(TranslationBlock *tb)
{
    GList *l;

    _gen_tpi_helper_depth++;

    int is_invalidate_opt = 0;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = tb->pc;
            tpi->_current_tb = tb;
            is_invalidate_opt |= tcg_plugin_tpi_before_exec_tb_invalidate_opt(tpi, tb);
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;

    return is_invalidate_opt;
}


/* Hook called before tblock executed.  */
void tcg_plugin_before_exec_tb(TranslationBlock *tb)
{
    GList *l;

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = tb->pc;
            tpi->_current_tb = tb;
            tcg_plugin_tpi_before_exec_tb(tpi, tb);
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}

/* Hook called after block executed.  */
void tcg_plugin_after_exec_tb(TranslationBlock *tb)
{
    GList *l;

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = tb->pc;
            tpi->_current_tb = tb;
            tcg_plugin_tpi_after_exec_tb(tpi, tb);
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}


/* Hook called before the instruction decoding. */
void tcg_plugin_before_decode_first_instr(TranslationBlock *tb)
{
    GList *l;

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = tb->pc;
            tpi->_current_tb = tb;
            tcg_plugin_tpi_before_decode_first_instr(tpi, tb);
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}


/* Hook called after the instruction decoding. */
void tcg_plugin_after_decode_last_instr(TranslationBlock *tb)
{
    GList *l;

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = tb->pc;
            tpi->_current_tb = tb;
            tcg_plugin_tpi_after_decode_last_instr(tpi, tb);
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}


/* Hook called each time before QEMU starts decoding a guest instruction.  */
void tcg_plugin_before_decode_instr(uint64_t pc)
{
    GList *l;

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }

        if (tcg_plugin_initialize(tpi)) {
            if (pc < tpi->low_pc || pc >= tpi->high_pc) {
                continue;
            }

            if (tpi->_in_gen_tpi_helper) {
                continue;
            }

            tpi->_in_gen_tpi_helper = true;

            if (tpi->before_decode_instr) {
                tpi->_current_pc = pc;
                TPI_CALLBACK_NOT_GENERIC(tpi, before_decode_instr, pc);
            }

            tpi->_in_gen_tpi_helper = false;
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}


/* Hook called each time a TCG opcode is generated.  */
void tcg_plugin_after_gen_opc(TCGOp *opcode, uint8_t nb_args)
{
    GList *l;

    _gen_tpi_helper_depth++;

    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (!tpi->_active) {
            continue;
        }
        if (tcg_plugin_initialize(tpi)) {
            tcg_plugin_tpi_after_gen_opc(tpi, opcode, nb_args);
        }
    }

    assert(_gen_tpi_helper_depth > 0);
    _gen_tpi_helper_depth--;
}

void tpi_exec_lock(const TCGPluginInterface *tpi)
{
    int err;
    (void)tpi;
    err = pthread_mutex_lock(&g_plugins_state.user_mutex);
    if (err != 0) {
        fprintf(stderr, "qemu: tpi_exec_lock: fatal error: %s\n",
                strerror(err));
        abort();
    }
}

void tpi_exec_unlock(const TCGPluginInterface *tpi)
{
    int err;
    (void)tpi;
    err = pthread_mutex_unlock(&g_plugins_state.user_mutex);
    if (err != 0) {
        fprintf(stderr, "qemu: tpi_exec_unlock: fatal error: %s\n",
                strerror(err));
        abort();
    }
}

uint64_t tpi_tb_address(const TranslationBlock *tb)
{
    return tb->pc;
}

extern uint32_t tpi_tb_size(const TranslationBlock *tb)
{
    return tb->size;
}

extern uint32_t tpi_tb_icount(const TranslationBlock *tb)
{
    return tb->icount;
}

static void add_parameter_to_plugin(const TCGPluginInterface *tpi,
                                    const char *name, void *value_ptr,
                                    void *default_value_ptr,
                                    enum TPI_PARAM_TYPE type,
                                    const char *description)
{
    assert(tpi);
    assert(name);
    assert(value_ptr);
    assert(default_value_ptr);

    switch (type) {
    case TPI_PARAM_TYPE_BOOL:
        *(bool *)(value_ptr) = *(bool *)(default_value_ptr);
        break;
    case TPI_PARAM_TYPE_INT:
        *(int64_t *)(value_ptr) = *(int64_t *)(default_value_ptr);
        break;
    case TPI_PARAM_TYPE_UINT:
        *(uint64_t *)(value_ptr) = *(uint64_t *)(default_value_ptr);
        break;
    case TPI_PARAM_TYPE_STRING:
        *(char **)(value_ptr) = g_strdup(*(const char **)(default_value_ptr));
        break;
    case TPI_PARAM_TYPE_DOUBLE:
        *(double *)(value_ptr) = *(double *)(default_value_ptr);
        break;
    }

    TPIParam *param = g_malloc0(sizeof(TPIParam));
    TPIParam_ctor(param, name, value_ptr, type, description);

    g_tree_replace(tpi->parameters, param->name, param);
}

void tpi_declare_param_bool(const TCGPluginInterface *tpi, const char *name,
                            bool *value_ptr, bool default_value,
                            const char *description)
{
    add_parameter_to_plugin(tpi, name, value_ptr, &default_value,
                            TPI_PARAM_TYPE_BOOL, description);
}

void tpi_declare_param_uint(const TCGPluginInterface *tpi, const char *name,
                            uint64_t *value_ptr, uint64_t default_value,
                            const char *description)
{
    add_parameter_to_plugin(tpi, name, value_ptr, &default_value,
                            TPI_PARAM_TYPE_UINT, description);
}

void tpi_declare_param_int(const TCGPluginInterface *tpi, const char *name,
                           int64_t *value_ptr, int64_t default_value,
                           const char *description)
{
    add_parameter_to_plugin(tpi, name, value_ptr, &default_value,
                            TPI_PARAM_TYPE_INT, description);
}

void tpi_declare_param_double(const TCGPluginInterface *tpi, const char *name,
                              double *value_ptr, double default_value,
                              const char *description)
{
    add_parameter_to_plugin(tpi, name, value_ptr, &default_value,
                            TPI_PARAM_TYPE_DOUBLE, description);
}

void tpi_declare_param_string(const TCGPluginInterface *tpi, const char *name,
                              char **value_ptr, const char *default_value,
                              const char *description)
{
    add_parameter_to_plugin(tpi, name, value_ptr, &default_value,
                            TPI_PARAM_TYPE_STRING, description);
}

static bool set_parameter_value(const TCGPluginInterface *tpi, const char *name,
                                void *new_value_ptr, char **error)
{
    TPIParam *p = get_parameter_pointer(tpi, name);

    char *tmp_error = NULL;

    if (!p) {
        tmp_error = g_strdup("parameter does not exist");
        goto error;
    }

    switch (p->type) {
    case TPI_PARAM_TYPE_BOOL: {
        bool value = *(bool *)new_value_ptr;
        bool *value_ptr = (bool *)p->value_ptr;
        if (tpi->check_param_bool &&
            !tpi->check_param_bool(tpi, name, *value_ptr, value, &tmp_error))
            goto error;
        *value_ptr = value;
    } break;
    case TPI_PARAM_TYPE_INT: {
        int64_t value = *(int64_t *)new_value_ptr;
        int64_t *value_ptr = (int64_t *)p->value_ptr;
        if (tpi->check_param_int &&
            !tpi->check_param_int(tpi, name, *value_ptr, value, &tmp_error))
            goto error;
        *value_ptr = value;
    } break;
    case TPI_PARAM_TYPE_UINT: {
        uint64_t value = *(uint64_t *)new_value_ptr;
        uint64_t *value_ptr = (uint64_t *)p->value_ptr;
        if (tpi->check_param_uint &&
            !tpi->check_param_uint(tpi, name, *value_ptr, value, &tmp_error))
            goto error;
        *value_ptr = value;
    } break;
    case TPI_PARAM_TYPE_STRING: {
        const char *value = *(const char **)new_value_ptr;
        char **value_ptr = (char **)p->value_ptr;
        if (tpi->check_param_string &&
            !tpi->check_param_string(tpi, name, *value_ptr, value, &tmp_error))
            goto error;
        g_free(*value_ptr);
        *value_ptr = g_strdup(value);
    } break;
    case TPI_PARAM_TYPE_DOUBLE: {
        double value = *(double *)new_value_ptr;
        double *value_ptr = (double *)p->value_ptr;
        if (tpi->check_param_double &&
            !tpi->check_param_double(tpi, name, *value_ptr, value, &tmp_error))
            goto error;
        *value_ptr = value;
    } break;
    }

    return true;
error:
    if (error == NULL) {
        g_free(tmp_error);
    } else {
        *error = tmp_error;
    }

    return false;
}

bool tpi_set_param_bool(const TCGPluginInterface *tpi, const char *name,
                        bool value, char **error)
{
    return set_parameter_value(tpi, name, &value, error);
}

bool tpi_set_param_uint(const TCGPluginInterface *tpi, const char *name,
                        uint64_t value, char **error)
{
    return set_parameter_value(tpi, name, &value, error);
}

bool tpi_set_param_int(const TCGPluginInterface *tpi, const char *name,
                       int64_t value, char **error)
{
    return set_parameter_value(tpi, name, &value, error);
}

bool tpi_set_param_double(const TCGPluginInterface *tpi, const char *name,
                          double value, char **error)
{
    return set_parameter_value(tpi, name, &value, error);
}

bool tpi_set_param_string(const TCGPluginInterface *tpi, const char *name,
                          const char *value, char **error)
{
    return set_parameter_value(tpi, name, &value, error);
}

static bool get_parameter_value(const TCGPluginInterface *tpi,
                                 const char *name, void *value_ptr)
{
    TPIParam *p = get_parameter_pointer(tpi, name);
    if (!p) {
        return false;
    }

    switch (p->type) {
    case TPI_PARAM_TYPE_BOOL: {
        bool value = false;
        if (!tpi->get_param_bool || !tpi->get_param_bool(tpi, name, &value)) {
            value = *(bool *)p->value_ptr;
        }
        *(bool *)value_ptr = value;
    } break;
    case TPI_PARAM_TYPE_INT: {
        int64_t value = 0;
        if (!tpi->get_param_int || !tpi->get_param_int(tpi, name, &value)) {
            value = *(int64_t *)p->value_ptr;
        }
        *(int64_t *)value_ptr = value;
    } break;
    case TPI_PARAM_TYPE_UINT: {
        uint64_t value = 0;
        if (!tpi->get_param_uint || !tpi->get_param_uint(tpi, name, &value)) {
            value = *(uint64_t *)p->value_ptr;
        }
        *(uint64_t *)value_ptr = value;
    } break;
    case TPI_PARAM_TYPE_STRING: {
        char *value = NULL;
        if (!tpi->get_param_string ||
            !tpi->get_param_string(tpi, name, &value)) {
            value = g_strdup(*(const char **)p->value_ptr);
        }
        *(char **)value_ptr = value;
    } break;
    case TPI_PARAM_TYPE_DOUBLE: {
        double value = 0;
        if (!tpi->get_param_double ||
            !tpi->get_param_double(tpi, name, &value)) {
            value = *(double *)p->value_ptr;
        }
        *(double *)value_ptr = value;
    } break;
    }

    return true;
}

bool tpi_get_param_bool(const TCGPluginInterface *tpi, const char *name,
                        bool *value)
{
    return get_parameter_value(tpi, name, value);
}

bool tpi_get_param_uint(const TCGPluginInterface *tpi, const char *name,
                        uint64_t *value)
{
    return get_parameter_value(tpi, name, value);
}

bool tpi_get_param_int(const TCGPluginInterface *tpi, const char *name,
                       int64_t *value)
{
    return get_parameter_value(tpi, name, value);
}

bool tpi_get_param_double(const TCGPluginInterface *tpi, const char *name,
                          double *value)
{
    return get_parameter_value(tpi, name, value);
}

bool tpi_get_param_string(const TCGPluginInterface *tpi, const char *name,
                          char **value)
{
    return get_parameter_value(tpi, name, value);
}

void tcg_plugin_initialize_all(void)
{
    {
        GList *l;
        for (l = g_plugins_state.tpi_list; l != NULL; l = l->next) {
            TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
            tcg_plugin_initialize(tpi);
        }
    }
}
