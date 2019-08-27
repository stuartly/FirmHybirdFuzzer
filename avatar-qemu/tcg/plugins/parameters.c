/*
 * TCG plugin for QEMU: set and get parameters
 *
 *
 * Copyright (C) 2017 STMicroelectronics
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

/*
 * parameters - Parameters example plugin
 *
 * Does nothing, just offer a set of parameters to configure/read.
 */

#include "tcg/tcg-plugin.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool param_bool;
static int64_t param_int;
static uint64_t param_uint;
static char *param_string;
static double param_double;

static bool check_bool(const TCGPluginInterface *tpi, const char *name,
                       bool old_value, bool new_value, char **error)
{
    return old_value != new_value;
}

static bool check_uint(const TCGPluginInterface *tpi, const char *name,
                       uint64_t old_value, uint64_t new_value, char **error)
{
    return old_value != new_value;
}

static bool check_int(const TCGPluginInterface *tpi, const char *name,
                      int64_t old_value, int64_t new_value, char **error)
{
    return old_value != new_value;
}

static bool check_double(const TCGPluginInterface *tpi, const char *name,
                         double old_value, double new_value, char **error)
{
    return old_value != new_value;
}

static bool check_string(const TCGPluginInterface *tpi, const char *name,
                         const char *old_value, const char *new_value,
                         char **error)
{
    return strcmp(old_value, new_value) != 0;
}

static bool get_return = false;

static bool get_bool(const TCGPluginInterface *tpi, const char *name,
                     bool *value)
{
    *value = false;
    return get_return;
}
static bool get_int(const TCGPluginInterface *tpi, const char *name,
                    int64_t *value)
{
    *value = 31;
    return get_return;
}
static bool get_uint(const TCGPluginInterface *tpi, const char *name,
                     uint64_t *value)
{
    *value = 24;
    return get_return;
}
static bool get_double(const TCGPluginInterface *tpi, const char *name,
                       double *value)
{
    *value = 1.4f;
    return get_return;
}
static bool get_string(const TCGPluginInterface *tpi, const char *name,
                       char **value)
{
    *value = g_strdup("new");
    return get_return;
}

bool status_active = false;
static void status_changed(bool new_status)
{
    status_active = new_status;
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);

    /* you don't have to set those callbacks to NULL,
     * just to show they exist */
    tpi->check_param_bool = NULL;
    tpi->check_param_int = NULL;
    tpi->check_param_uint = NULL;
    tpi->check_param_string = NULL;
    tpi->check_param_double = NULL;
    tpi->get_param_bool = NULL;
    tpi->get_param_int = NULL;
    tpi->get_param_uint = NULL;
    tpi->get_param_string = NULL;
    tpi->get_param_double = NULL;
    tpi->active_changed = NULL;

    // declare param
    tpi_declare_param_bool(tpi, "param_bool", &param_bool, true, "Bool param");
    tpi_declare_param_uint(tpi, "param_uint", &param_uint, 42, "Uint param");
    tpi_declare_param_int(tpi, "param_int", &param_int, -42, "Int param");
    tpi_declare_param_double(tpi, "param_double", &param_double, 18.45,
                             "Double param");
    tpi_declare_param_string(tpi, "param_string", &param_string, "Welcome!",
                             "String param");

    TCGPluginInterface *me = NULL;
    me = tpi_find_plugin(NULL, -1);
    assert(!me);
    me = tpi_find_plugin(NULL, tpi->id);
    assert(me == tpi);
    me = tpi_find_plugin("param", -1);
    assert(me == tpi);

    bool b = false;
    uint64_t u = 0;
    int64_t i = 0;
    char *s = 0;
    double d = 0;

    // read value
    assert(tpi_get_param_bool(me, "param_bool", &b) && b == true);
    assert(tpi_get_param_uint(me, "param_uint", &u) && u == 42);
    assert(tpi_get_param_int(me, "param_int", &i) && i == -42);
    assert(tpi_get_param_double(me, "param_double", &d) && d == 18.45);
    assert(tpi_get_param_string(me, "param_string", &s) &&
           strcmp(s, "Welcome!") == 0);
    g_free(s);
    assert(!tpi_get_param_string(me, "param_fake", &s));

    // set value
    char *error = NULL;
    assert(tpi_set_param_bool(tpi, "param_bool", false, &error) &&
           param_bool == false);
    assert(tpi_set_param_uint(tpi, "param_uint", 14, &error) &&
           param_uint == 14);
    assert(tpi_set_param_int(tpi, "param_int", 16, &error) && param_int == 16);
    assert(tpi_set_param_double(tpi, "param_double", 14.23, &error) &&
           param_double == 14.23);
    assert(tpi_set_param_string(tpi, "param_string", "lol", &error) &&
           strcmp(param_string, "lol") == 0);
    assert(!tpi_set_param_string(tpi, "param_fake", "lol", &error));

    // get new value
    assert(tpi_get_param_bool(me, "param_bool", &b) && b == false);
    assert(tpi_get_param_uint(me, "param_uint", &u) && u == 14);
    assert(tpi_get_param_int(me, "param_int", &i) && i == 16);
    assert(tpi_get_param_double(me, "param_double", &d) && d == 14.23);
    assert(tpi_get_param_string(me, "param_string", &s) &&
           strcmp(s, "lol") == 0);
    g_free(s);

    // check new values
    tpi->check_param_bool = &check_bool;
    tpi->check_param_int = &check_int;
    tpi->check_param_uint = &check_uint;
    tpi->check_param_string = &check_string;
    tpi->check_param_double = &check_double;

    // refuse new values if same
    assert(!tpi_set_param_bool(tpi, "param_bool", false, &error));
    assert(!tpi_set_param_uint(tpi, "param_uint", 14, &error));
    assert(!tpi_set_param_int(tpi, "param_int", 16, &error));
    assert(!tpi_set_param_double(tpi, "param_double", 14.23, &error));
    assert(!tpi_set_param_string(tpi, "param_string", "lol", &error));
    // accept new values if different
    assert(tpi_set_param_bool(tpi, "param_bool", true, &error));
    assert(tpi_set_param_uint(tpi, "param_uint", 15, &error));
    assert(tpi_set_param_int(tpi, "param_int", 17, &error));
    assert(tpi_set_param_double(tpi, "param_double", 15.23, &error));
    assert(tpi_set_param_string(tpi, "param_string", "lola", &error));

    // special getter
    tpi->get_param_bool = &get_bool;
    tpi->get_param_int = &get_int;
    tpi->get_param_uint = &get_uint;
    tpi->get_param_string = &get_string;
    tpi->get_param_double = &get_double;

    get_return = false; // value is read from memory like before
    assert(tpi_get_param_bool(me, "param_bool", &b) && b == true);
    assert(tpi_get_param_uint(me, "param_uint", &u) && u == 15);
    assert(tpi_get_param_int(me, "param_int", &i) && i == 17);
    assert(tpi_get_param_double(me, "param_double", &d) && d == 15.23);
    assert(tpi_get_param_string(me, "param_string", &s) &&
           strcmp(s, "lola") == 0);
    g_free(s);

    get_return = true; // special value is returned from function
    assert(tpi_get_param_bool(me, "param_bool", &b) && b == false);
    assert(tpi_get_param_uint(me, "param_uint", &u) && u == 24);
    assert(tpi_get_param_int(me, "param_int", &i) && i == 31);
    assert(tpi_get_param_double(me, "param_double", &d) && d == 1.4f);
    assert(tpi_get_param_string(me, "param_string", &s) &&
           strcmp(s, "new") == 0);
    g_free(s);

    // activate / deactivate plugin
    assert(!status_active);
    tpi->active_changed = &status_changed;
    tpi_set_active(tpi, true);
    assert(status_active);
    tpi_set_active(tpi, false);
    assert(!status_active);


    tpi->check_param_bool = NULL;
    tpi->check_param_int = NULL;
    tpi->check_param_uint = NULL;
    tpi->check_param_string = NULL;
    tpi->check_param_double = NULL;
    tpi->get_param_bool = NULL;
    tpi->get_param_int = NULL;
    tpi->get_param_uint = NULL;
    tpi->get_param_string = NULL;
    tpi->get_param_double = NULL;
    tpi->active_changed = NULL;
}
