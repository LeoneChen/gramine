/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */
/* Copyright (C) 2021 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include <stdarg.h>
#include <stdint.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_ipc.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_thread.h"
#include "pal.h"
#include "pal_arch.h"

int g_log_level = LOG_LEVEL_NONE;

/* NOTE: We could add "libos" prefix to the below strings for more fine-grained log info */
static const char* log_level_to_prefix[] = {
    [LOG_LEVEL_NONE]    = "",
    [LOG_LEVEL_ERROR]   = "error: ",
    [LOG_LEVEL_WARNING] = "warning: ",
    [LOG_LEVEL_DEBUG]   = "debug: ",
    [LOG_LEVEL_TRACE]   = "trace: ",
    [LOG_LEVEL_ALL]     = "", // not a valid entry actually (no public wrapper uses this log level)
};

void log_setprefix(libos_tcb_t* tcb) {
    if (g_log_level <= LOG_LEVEL_NONE)
        return;

    lock(&g_process.fs_lock);

    const char* exec_name;
    if (g_process.exec) {
        if (g_process.exec->dentry) {
            exec_name = g_process.exec->dentry->name;
        } else {
            /* Unknown executable name */
            exec_name = "?";
        }
    } else {
        /* `g_process.exec` not available yet, happens on process init */
        exec_name = "";
    }

    uint32_t vmid = g_process_ipc_ids.self_vmid;
    size_t total_len;
    if (tcb->tp) {
        if (!is_internal(tcb->tp)) {
            /* normal app thread: show Process ID, Thread ID, and exec name */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:T%u:%s] ",
                                 vmid, tcb->tp->tid, exec_name);
        } else {
            /* internal LibOS thread: show Process ID and Internal-thread marker */
            total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u:libos] ",
                                 vmid);
        }
    } else if (vmid) {
        /* unknown thread (happens on process init): show just Process ID and exec name */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[P%u::%s] ", vmid,
                             exec_name);
    } else {
        /* unknown process (happens on process init): show exec name */
        total_len = snprintf(tcb->log_prefix, ARRAY_SIZE(tcb->log_prefix), "[::%s] ", exec_name);
    }
    if (total_len > ARRAY_SIZE(tcb->log_prefix) - 1) {
        /* exec name too long, snip it */
        const char* snip = "...] ";
        size_t snip_size = strlen(snip) + 1;
        memcpy(tcb->log_prefix + ARRAY_SIZE(tcb->log_prefix) - snip_size, snip, snip_size);
    }

    unlock(&g_process.fs_lock);
}

static int buf_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    PalDebugLog(str, size);
    return 0;
}

void libos_log(int level, const char* file, const char* func, uint64_t line, const char* fmt, ...) {
    if (level <= g_log_level) {
        struct print_buf buf = INIT_PRINT_BUF(buf_write_all);

        if (LOG_LEVEL_DEBUG <= g_log_level) {
            buf_printf(&buf, "(%s:%lu:%s) ", file, line, func);
        }

        buf_puts(&buf, libos_get_tcb()->log_prefix);
        buf_puts(&buf, log_level_to_prefix[level]);

        va_list ap;
        va_start(ap, fmt);
        buf_vprintf(&buf, fmt, ap);
        va_end(ap);
        buf_printf(&buf, "\n");

        buf_flush(&buf);
    }
}

void libos_capture_stack_trace(char* buf, size_t buf_sz, PAL_CONTEXT* regs) {
    if (!regs || buf_sz == 0)
        return;

    struct libos_thread* cur_thread = get_cur_thread();
    if (!cur_thread)
        return;

    uintptr_t stack_lo = (uintptr_t)cur_thread->stack;
    uintptr_t stack_hi = (uintptr_t)cur_thread->stack_top;

    char* p = buf;
    char* end = buf + buf_sz - 1;

    /* Frame 0: rip (syscall call site, inside libc) */
    uintptr_t rip = regs->rip;
    int n = snprintf(p, end - p, "0x%lx ", rip);
    if (n > 0 && p + n < end) p += n;

    /* Frame 1: *rsp = return address to direct caller (missing frame for -O2 libc) */
    uintptr_t rsp = regs->rsp;
    if (IS_ALIGNED(rsp, 8) && rsp > stack_lo && rsp < stack_hi) {
        uintptr_t ret_addr = *(uintptr_t*)rsp;
        if (ret_addr) {
            n = snprintf(p, end - p, "0x%lx ", ret_addr);
            if (n > 0 && p + n < end) p += n;
        }
    }

    /* Frame 2+: walk rbp chain within stack bounds */
    uintptr_t rbp = regs->rbp;
    uintptr_t prev_rbp = 0;
    for (int i = 0; i < 50; i++) {
        if (!IS_ALIGNED(rbp, 8) || rbp <= prev_rbp || rbp <= stack_lo || rbp >= stack_hi)
            break;
        uintptr_t ret = *(uintptr_t*)(rbp + 8);
        if (!ret) break;
        n = snprintf(p, end - p, "0x%lx ", ret);
        if (n <= 0 || p + n >= end) break;
        p += n;
        prev_rbp = rbp;
        rbp = *(uintptr_t*)rbp;
    }
}
