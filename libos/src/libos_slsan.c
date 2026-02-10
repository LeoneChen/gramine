#include <execinfo.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "api.h"
#include "libos_process.h"
#include "log.h"

extern void* slsan_syscall_context[256][256];

static __attribute_used__ void get_ip_offset(uintptr_t addr, char* buf, size_t buf_sz) {
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    libos_describe_location(addr, buf, buf_sz);

    size_t length   = buf_sz - 1;
    char* paren_pos = strchr(buf, '(');
    if (paren_pos) {
        length = paren_pos - buf - 1;
    }

    buf[length] = '\0';
}

static void get_backtrace(char* out_buf, size_t out_buf_sz) {
    if (out_buf == NULL || out_buf_sz == 0) {
        return;
    }
    struct libos_thread* cur_thread = get_cur_thread();
    if (cur_thread != NULL && slsan_syscall_context[g_process.pid][cur_thread->tid] != NULL) {
        PAL_CONTEXT* context = (PAL_CONTEXT*)slsan_syscall_context[g_process.pid][cur_thread->tid];
        void* rbp            = (void*)context->rbp;
        void* prev_rbp       = NULL;
        int offset           = 0;
        int depth            = 0;
#if FAST_IP_OFFSET
        offset += snprintf(out_buf + offset, out_buf_sz - offset, " 0x%lx", context->rip);
#else
        char ip_offset[BUFSIZ];
        ip_offset[0] = '\0';
        get_ip_offset(context->rip, ip_offset, sizeof(ip_offset));
        offset += snprintf(out_buf + offset, out_buf_sz - offset, " %s", ip_offset);
#endif

        if ((context->rsp > (uintptr_t)cur_thread->stack) &&
            (context->rsp < (uintptr_t)cur_thread->stack_top)) {
            uintptr_t ret_addr = (uintptr_t)*(void**)context->rsp;
#if FAST_IP_OFFSET
            offset += snprintf(out_buf + offset, out_buf_sz - offset, " 0x%lx", ret_addr);
#else
            get_ip_offset(ret_addr, ip_offset, sizeof(ip_offset));
            offset += snprintf(out_buf + offset, out_buf_sz - offset, " %s", ip_offset);
#endif
        }

        while ((depth < 50) &&                            // depth is less than 50
               ((uintptr_t)rbp > (uintptr_t)prev_rbp) &&  // rbp is greater than previous rbp
               ((uintptr_t)rbp > (uintptr_t)cur_thread->stack) &&   // rbp is greater than stack
               ((uintptr_t)rbp < (uintptr_t)cur_thread->stack_top)  // rbp is less than stack top
        ) {
            uintptr_t ret_addr = (uintptr_t)*(void**)(rbp + 8);
            prev_rbp           = rbp;
            rbp                = *(void**)rbp;
            depth++;

#if FAST_IP_OFFSET
            offset += snprintf(out_buf + offset, out_buf_sz - offset, " 0x%lx", ret_addr);
#else
            get_ip_offset(ret_addr, ip_offset, sizeof(ip_offset));
            offset += snprintf(out_buf + offset, out_buf_sz - offset, " %s", ip_offset);
#endif
        }
    }
}

void log_file_pos(const char* where, bool is_write, void* hdl, uint64_t hdl_id, void* hdl_pos,
                  char* hdl_uri, void* real_pos, file_off_t orig_pos_value,
                  file_off_t new_pos_value) {
    if (hdl_uri != NULL && strstr(hdl_uri, "slsan") != NULL) {
        return;
    }
    (void)hdl_pos;
    (void)real_pos;
    if (LOG_LEVEL_WARNING <= g_log_level) {
        char bt[BUFSIZ];
        bt[0] = '\0';
        get_backtrace(bt, sizeof(bt));
        if (is_write) {
            log_warning(
                "[PID: %d TID: %d] write (%ld->%ld) in %s: hdl=%p, hdl_id=%ld, hdl_uri=%s, bt:%s",
                g_process.pid, get_cur_tid(), orig_pos_value, new_pos_value, where, hdl, hdl_id,
                hdl_uri, bt);
        } else {
            log_warning("[PID: %d TID: %d] read (%ld) in %s: hdl=%p, hdl_id=%ld, hdl_uri=%s, bt:%s",
                        g_process.pid, get_cur_tid(), orig_pos_value, where, hdl, hdl_id, hdl_uri,
                        bt);
        }
    }
}