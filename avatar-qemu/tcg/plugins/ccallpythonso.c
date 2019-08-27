// gcc ccallpythonso.c `python3.5-config --cflags` `python3.5-config --ldflags` -fPIC -shared -o ccallpythonso.so

#include <stdio.h>
#include <stdlib.h>
#include "python3.5m/Python.h"

PyObject *pModule = NULL;
PyObject *pFunc = NULL;
PyObject *pArgs = NULL;
PyObject *pRet = NULL;

#define DECREF_PYOBJ(pyobj) do { \
    if (pyobj) {                 \
        Py_DECREF(pyobj);        \
        pyobj = NULL;            \
    }                            \
} while (0);

#define ERR_PRINT(fmt, ...) printf("%s" fmt "\n", "[-] ", ##__VA_ARGS__);
#define SUC_PRINT(fmt, ...) printf("%s" fmt "\n", "[+] ", ##__VA_ARGS__);
#define LOG_PRINT(fmt, ...) printf("%s" fmt "\n", "[In .so file] ", ##__VA_ARGS__);

void Decref_Pyobj(void)
{
    DECREF_PYOBJ(pModule);
    DECREF_PYOBJ(pFunc);
    DECREF_PYOBJ(pArgs);
    DECREF_PYOBJ(pRet);
}

int Init_Py(void)
{
    // Py_SetPythonHome(L"/home/stly/.virtualenvs/IoTFuzz/bin");
    // printf("%s\n", Py_GetVersion());
    if(!Py_IsInitialized()) {
        Py_Initialize();
    }
    
    if(!Py_IsInitialized()) {
        PyErr_Print();
        ERR_PRINT("Python init failed!");
        return -1;
    }

    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/hybridFuzz/hybridFuzz')");

    return 1;
}

// function signature as same as Init_py()
int Uninit_Py(void)
{
    Decref_Pyobj();
    Py_Finalize();
    return 0;
}

void NoPara_NoRet(const char *p_module, const char *p_func)
{
    pModule = PyImport_ImportModule(p_module);
    if(!pModule) {
        PyErr_Print();
        ERR_PRINT("Load %s.py failed!", p_module);
        return;
    }

    pFunc = PyObject_GetAttrString(pModule, p_func);
    if(!pFunc || !PyCallable_Check(pFunc)) {
        PyErr_Print();
        ERR_PRINT("Can't find %s function!", p_func);
    }

    pRet = PyObject_CallObject(pFunc, NULL);
    if (pRet != NULL) {
        SUC_PRINT("c call python success!");
    }

    Decref_Pyobj();
}

// call Init_Py() before calling this function!
void String_NoRet(const char *p_module, const char *p_func, const char *para_str)
{
    pModule = PyImport_ImportModule(p_module);
    if(!pModule) {
        PyErr_Print();
        ERR_PRINT("Load %s.py failed!", p_module);
        return;
    }
    
    pFunc = PyObject_GetAttrString(pModule, p_func);
    if(!pFunc || !PyCallable_Check(pFunc)) {
        PyErr_Print();
        ERR_PRINT("Can't find %s function!", p_func);
    }

    pArgs = PyTuple_New(1);
    PyTuple_SetItem(pArgs, 0, Py_BuildValue("s", para_str));

    pRet = PyObject_CallObject(pFunc, pArgs);
    if (pRet != NULL) {
        SUC_PRINT("c call python(%s.%s) success!", p_module, p_func);
    }
    
    Decref_Pyobj();
}

/**
 * caller should free the area of return pointer!
 *          ____________________________________
 * return: | len, 4 bytes | real buf, len bytes |, total len+4 bytes.
 *          ------------------------------------
 */ 
unsigned char *StrAndInt_u8ptr(const char *p_module, const char *p_func, const char *para_str, const int para_int1, const int para_int2)
{
    int ret_len = 0;
    unsigned char *ret_bytearray = NULL;
    pModule = PyImport_ImportModule(p_module);
    if(!pModule) {
        PyErr_Print();
        ERR_PRINT("Load %s.py failed!", p_module);
    }
    else {
        pFunc = PyObject_GetAttrString(pModule, p_func);
        if(!pFunc || !PyCallable_Check(pFunc)) {
            PyErr_Print();
            ERR_PRINT("Can't find %s function!", p_func);
        }

        pArgs = PyTuple_New(3);
        PyTuple_SetItem(pArgs, 0, Py_BuildValue("s", para_str));
        PyTuple_SetItem(pArgs, 1, Py_BuildValue("i", para_int1));
        PyTuple_SetItem(pArgs, 2, Py_BuildValue("i", para_int2));

        pRet = PyObject_CallObject(pFunc, pArgs);
        
        if (pRet != NULL) {
            ret_bytearray = (unsigned char*)PyByteArray_AsString(pRet);
            ret_len = PyByteArray_Size(pRet);
            SUC_PRINT("c call python(%s.%s) success!", p_module, p_func);
        }
    }

    unsigned char *ret_u8_str = (unsigned char*)malloc(ret_len+sizeof(int));
    memcpy(ret_u8_str, &ret_len, sizeof(int));
    if (ret_bytearray != NULL) {
        SUC_PRINT("python has return to caller!");
        memcpy(ret_u8_str+sizeof(int), ret_bytearray, ret_len);
    }

    Decref_Pyobj();
    return ret_u8_str; // caller should free it!
}

int main(void) {
    Init_Py();
    NoPara_NoRet("fuzz", "Trigger_New_B2B");
    Uninit_Py();
    return 0;
}
