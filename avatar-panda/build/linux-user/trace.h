/* This file is autogenerated by tracetool, do not edit. */

#ifndef TRACE_LINUX_USER_GENERATED_TRACERS_H
#define TRACE_LINUX_USER_GENERATED_TRACERS_H

#include "qemu-common.h"
#include "trace/control.h"

extern TraceEvent _TRACE_USER_SETUP_FRAME_EVENT;
extern TraceEvent _TRACE_USER_SETUP_RT_FRAME_EVENT;
extern TraceEvent _TRACE_USER_DO_RT_SIGRETURN_EVENT;
extern TraceEvent _TRACE_USER_DO_SIGRETURN_EVENT;
extern TraceEvent _TRACE_USER_FORCE_SIG_EVENT;
extern TraceEvent _TRACE_USER_HANDLE_SIGNAL_EVENT;
extern TraceEvent _TRACE_USER_HOST_SIGNAL_EVENT;
extern TraceEvent _TRACE_USER_QUEUE_SIGNAL_EVENT;
extern TraceEvent _TRACE_USER_S390X_RESTORE_SIGREGS_EVENT;
extern uint16_t _TRACE_USER_SETUP_FRAME_DSTATE;
extern uint16_t _TRACE_USER_SETUP_RT_FRAME_DSTATE;
extern uint16_t _TRACE_USER_DO_RT_SIGRETURN_DSTATE;
extern uint16_t _TRACE_USER_DO_SIGRETURN_DSTATE;
extern uint16_t _TRACE_USER_FORCE_SIG_DSTATE;
extern uint16_t _TRACE_USER_HANDLE_SIGNAL_DSTATE;
extern uint16_t _TRACE_USER_HOST_SIGNAL_DSTATE;
extern uint16_t _TRACE_USER_QUEUE_SIGNAL_DSTATE;
extern uint16_t _TRACE_USER_S390X_RESTORE_SIGREGS_DSTATE;
#define TRACE_USER_SETUP_FRAME_ENABLED 1
#define TRACE_USER_SETUP_RT_FRAME_ENABLED 1
#define TRACE_USER_DO_RT_SIGRETURN_ENABLED 1
#define TRACE_USER_DO_SIGRETURN_ENABLED 1
#define TRACE_USER_FORCE_SIG_ENABLED 1
#define TRACE_USER_HANDLE_SIGNAL_ENABLED 1
#define TRACE_USER_HOST_SIGNAL_ENABLED 1
#define TRACE_USER_QUEUE_SIGNAL_ENABLED 1
#define TRACE_USER_S390X_RESTORE_SIGREGS_ENABLED 1
#include "qemu/log.h"


static inline void trace_user_setup_frame(void * env, uint64_t frame_addr)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_SETUP_FRAME)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_setup_frame " "env=%p frame_addr=%"PRIx64 "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, frame_addr);
        }
    }
}

static inline void trace_user_setup_rt_frame(void * env, uint64_t frame_addr)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_SETUP_RT_FRAME)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_setup_rt_frame " "env=%p frame_addr=%"PRIx64 "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, frame_addr);
        }
    }
}

static inline void trace_user_do_rt_sigreturn(void * env, uint64_t frame_addr)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_DO_RT_SIGRETURN)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_do_rt_sigreturn " "env=%p frame_addr=%"PRIx64 "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, frame_addr);
        }
    }
}

static inline void trace_user_do_sigreturn(void * env, uint64_t frame_addr)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_DO_SIGRETURN)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_do_sigreturn " "env=%p frame_addr=%"PRIx64 "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, frame_addr);
        }
    }
}

static inline void trace_user_force_sig(void * env, int target_sig, int host_sig)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_FORCE_SIG)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_force_sig " "env=%p signal %d (host %d)" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, target_sig, host_sig);
        }
    }
}

static inline void trace_user_handle_signal(void * env, int target_sig)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_HANDLE_SIGNAL)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_handle_signal " "env=%p signal %d" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, target_sig);
        }
    }
}

static inline void trace_user_host_signal(void * env, int host_sig, int target_sig)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_HOST_SIGNAL)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_host_signal " "env=%p signal %d (target %d(" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, host_sig, target_sig);
        }
    }
}

static inline void trace_user_queue_signal(void * env, int target_sig)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_QUEUE_SIGNAL)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_queue_signal " "env=%p signal %d" "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, target_sig);
        }
    }
}

static inline void trace_user_s390x_restore_sigregs(void * env, uint64_t sc_psw_addr, uint64_t env_psw_addr)
{
    if (true) {
        if (trace_event_get_state(TRACE_USER_S390X_RESTORE_SIGREGS)) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
            qemu_log_mask(LOG_TRACE, "%d@%zd.%06zd:user_s390x_restore_sigregs " "env=%p frame psw.addr %"PRIx64 " current psw.addr %"PRIx64 "\n",
                          getpid(),
                          (size_t)_now.tv_sec, (size_t)_now.tv_usec
                          , env, sc_psw_addr, env_psw_addr);
        }
    }
}
#endif /* TRACE_LINUX_USER_GENERATED_TRACERS_H */
