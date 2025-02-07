/* This file is autogenerated by tracetool, do not edit. */

#ifndef TRACE_HW_NVRAM_GENERATED_TRACERS_H
#define TRACE_HW_NVRAM_GENERATED_TRACERS_H

#include "qemu-common.h"
#include "trace/control.h"

extern TraceEvent _TRACE_NVRAM_READ_EVENT;
extern TraceEvent _TRACE_NVRAM_WRITE_EVENT;
extern TraceEvent _TRACE_FW_CFG_SELECT_EVENT;
extern TraceEvent _TRACE_FW_CFG_READ_EVENT;
extern TraceEvent _TRACE_FW_CFG_ADD_FILE_EVENT;
extern uint16_t _TRACE_NVRAM_READ_DSTATE;
extern uint16_t _TRACE_NVRAM_WRITE_DSTATE;
extern uint16_t _TRACE_FW_CFG_SELECT_DSTATE;
extern uint16_t _TRACE_FW_CFG_READ_DSTATE;
extern uint16_t _TRACE_FW_CFG_ADD_FILE_DSTATE;
#define TRACE_NVRAM_READ_ENABLED 1
#define TRACE_NVRAM_WRITE_ENABLED 1
#define TRACE_FW_CFG_SELECT_ENABLED 1
#define TRACE_FW_CFG_READ_ENABLED 1
#define TRACE_FW_CFG_ADD_FILE_ENABLED 1
#include "qemu/log.h"


static inline void trace_nvram_read(uint32_t addr, uint32_t ret)
{
    if (true) {
        if (trace_event_get_state(TRACE_NVRAM_READ)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:nvram_read " "read addr %d: 0x%02x" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , addr, ret);
        }
    }
}

static inline void trace_nvram_write(uint32_t addr, uint32_t old, uint32_t val)
{
    if (true) {
        if (trace_event_get_state(TRACE_NVRAM_WRITE)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:nvram_write " "write addr %d: 0x%02x -> 0x%02x" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , addr, old, val);
        }
    }
}

static inline void trace_fw_cfg_select(void * s, uint16_t key, int ret)
{
    if (true) {
        if (trace_event_get_state(TRACE_FW_CFG_SELECT)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:fw_cfg_select " "%p key %d = %d" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , s, key, ret);
        }
    }
}

static inline void trace_fw_cfg_read(void * s, uint64_t ret)
{
    if (true) {
        if (trace_event_get_state(TRACE_FW_CFG_READ)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:fw_cfg_read " "%p = %"PRIx64 "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , s, ret);
        }
    }
}

static inline void trace_fw_cfg_add_file(void * s, int index, char * name, size_t len)
{
    if (true) {
        if (trace_event_get_state(TRACE_FW_CFG_ADD_FILE)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:fw_cfg_add_file " "%p #%d: %s (%zd bytes)" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , s, index, name, len);
        }
    }
}
#endif /* TRACE_HW_NVRAM_GENERATED_TRACERS_H */
