/* This file is autogenerated by tracetool, do not edit. */

#ifndef TRACE_HW_ISA_GENERATED_TRACERS_H
#define TRACE_HW_ISA_GENERATED_TRACERS_H

#include "qemu-common.h"
#include "trace/control.h"

extern TraceEvent _TRACE_PC87312_IO_READ_EVENT;
extern TraceEvent _TRACE_PC87312_IO_WRITE_EVENT;
extern TraceEvent _TRACE_PC87312_INFO_FLOPPY_EVENT;
extern TraceEvent _TRACE_PC87312_INFO_IDE_EVENT;
extern TraceEvent _TRACE_PC87312_INFO_PARALLEL_EVENT;
extern TraceEvent _TRACE_PC87312_INFO_SERIAL_EVENT;
extern uint16_t _TRACE_PC87312_IO_READ_DSTATE;
extern uint16_t _TRACE_PC87312_IO_WRITE_DSTATE;
extern uint16_t _TRACE_PC87312_INFO_FLOPPY_DSTATE;
extern uint16_t _TRACE_PC87312_INFO_IDE_DSTATE;
extern uint16_t _TRACE_PC87312_INFO_PARALLEL_DSTATE;
extern uint16_t _TRACE_PC87312_INFO_SERIAL_DSTATE;
#define TRACE_PC87312_IO_READ_ENABLED 1
#define TRACE_PC87312_IO_WRITE_ENABLED 1
#define TRACE_PC87312_INFO_FLOPPY_ENABLED 1
#define TRACE_PC87312_INFO_IDE_ENABLED 1
#define TRACE_PC87312_INFO_PARALLEL_ENABLED 1
#define TRACE_PC87312_INFO_SERIAL_ENABLED 1
#include "qemu/log.h"


static inline void trace_pc87312_io_read(uint32_t addr, uint32_t val)
{
    if (true) {
        if (trace_event_get_state(TRACE_PC87312_IO_READ)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:pc87312_io_read " "read addr=%x val=%x" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , addr, val);
        }
    }
}

static inline void trace_pc87312_io_write(uint32_t addr, uint32_t val)
{
    if (true) {
        if (trace_event_get_state(TRACE_PC87312_IO_WRITE)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:pc87312_io_write " "write addr=%x val=%x" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , addr, val);
        }
    }
}

static inline void trace_pc87312_info_floppy(uint32_t base)
{
    if (true) {
        if (trace_event_get_state(TRACE_PC87312_INFO_FLOPPY)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:pc87312_info_floppy " "base 0x%x" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , base);
        }
    }
}

static inline void trace_pc87312_info_ide(uint32_t base)
{
    if (true) {
        if (trace_event_get_state(TRACE_PC87312_INFO_IDE)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:pc87312_info_ide " "base 0x%x" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , base);
        }
    }
}

static inline void trace_pc87312_info_parallel(uint32_t base, uint32_t irq)
{
    if (true) {
        if (trace_event_get_state(TRACE_PC87312_INFO_PARALLEL)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:pc87312_info_parallel " "base 0x%x, irq %u" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , base, irq);
        }
    }
}

static inline void trace_pc87312_info_serial(int n, uint32_t base, uint32_t irq)
{
    if (true) {
        if (trace_event_get_state(TRACE_PC87312_INFO_SERIAL)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:pc87312_info_serial " "id=%d, base 0x%x, irq %u" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , n, base, irq);
        }
    }
}
#endif /* TRACE_HW_ISA_GENERATED_TRACERS_H */
