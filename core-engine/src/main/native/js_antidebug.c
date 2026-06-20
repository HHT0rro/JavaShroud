#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "js_antidebug.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

#if defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#endif

#if defined(__APPLE__)
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#endif

/* Best-effort anti-dump hardening. Non-Linux targets are no-ops to preserve the cross-compile matrix. */
JS_HIDDEN void js_native_anti_dump_harden(void) {
#if defined(__linux__) || defined(__ANDROID__)
    extern int prctl(int, ...);
    (void)prctl(4 /* PR_SET_DUMPABLE */, 0, 0, 0, 0);
#endif
}

static int js_vm_syscall_tracer_pid_present(void) {
#if defined(__linux__) || defined(__ANDROID__)
    int fd = -1;
#if defined(SYS_openat)
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/status", O_RDONLY, 0);
#elif defined(SYS_open)
    fd = (int)syscall(SYS_open, "/proc/self/status", O_RDONLY, 0);
#else
    fd = open("/proc/self/status", O_RDONLY);
#endif
    if (fd < 0) return 0;
    char buf[1024];
    int found = 0;
    ssize_t n;
    while ((n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;
        const char *needle = strstr(buf, "TracerPid:");
        if (needle) {
            needle += 10;
            while (*needle == ' ' || *needle == '\t') needle++;
            long pid = strtol(needle, NULL, 10);
            if (pid > 0) found = 1;
            break;
        }
        if (n < (ssize_t)(sizeof(buf) - 1)) break;
    }
    syscall(SYS_close, fd);
    return found;
#else
    return 0;
#endif
}

static int js_vm_syscall_ptrace_child_probe(void) {
#if (defined(__linux__) || defined(__ANDROID__)) && defined(SYS_ptrace)
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        errno = 0;
        long rc = syscall(SYS_ptrace, 0L, 0L, 0L, 0L);
        _exit((rc == 0) ? 0 : (errno == EPERM ? 1 : 0));
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return 0;
    if (!WIFEXITED(status)) return 0;
    return WEXITSTATUS(status) == 1 ? 1 : 0;
#else
    return 0;
#endif
}

static int js_vm_win_peb_being_debugged(void) {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    unsigned char *peb = (unsigned char*)__readgsqword(0x60);
    if (!peb) return 0;
    if (peb[0x02] != 0) return 1;
    unsigned int nt_global_flag = *(unsigned int*)(peb + 0xBC);
    if ((nt_global_flag & 0x70u) != 0) return 1;
    return 0;
#elif defined(_WIN32) && (defined(_M_IX86) || defined(__i386__))
    unsigned char *peb = (unsigned char*)__readfsdword(0x30);
    if (!peb) return 0;
    if (peb[0x02] != 0) return 1;
    unsigned int nt_global_flag = *(unsigned int*)(peb + 0x68);
    if ((nt_global_flag & 0x70u) != 0) return 1;
    return 0;
#else
    return 0;
#endif
}

static int js_vm_win_debug_port_present(void) {
#if defined(_WIN32)
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    typedef LONG (WINAPI *NtQIP)(HANDLE, unsigned int, void*, unsigned long, unsigned long*);
    NtQIP nt_query = (NtQIP)(void*)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!nt_query) return 0;
    void *debug_port = NULL;
    LONG status = nt_query((HANDLE)(intptr_t)-1, 7u, &debug_port, (unsigned long)sizeof(debug_port), NULL);
    if (status == 0 && debug_port != NULL) return 1;
    unsigned int debug_flags = 1;
    status = nt_query((HANDLE)(intptr_t)-1, 31u, &debug_flags, (unsigned long)sizeof(debug_flags), NULL);
    if (status == 0 && debug_flags == 0) return 1;
#endif
    return 0;
}

static int js_vm_mac_sysctl_traced(void) {
#if defined(__APPLE__)
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0 ? 1 : 0;
#else
    return 0;
#endif
}

static int js_vm_strong_debugger_probe_now(void) {
    int signals = 0;
#if defined(__linux__) || defined(__ANDROID__)
    if (js_vm_syscall_tracer_pid_present()) signals++;
    if (js_vm_syscall_ptrace_child_probe()) signals++;
#elif defined(_WIN32)
    if (js_vm_win_peb_being_debugged()) signals++;
    if (js_vm_win_debug_port_present()) signals++;
#elif defined(__APPLE__)
    if (js_vm_mac_sysctl_traced()) signals++;
#endif
    return signals > 0 ? 1 : 0;
}

#define JS_VM_STRONG_DBG_PROBE_PERIOD 64

JS_HIDDEN int js_vm_strong_debugger_present(void) {
    static int probe_countdown = 0;
    static int cached_verdict = 0;
    if (probe_countdown <= 0) {
        cached_verdict = js_vm_strong_debugger_probe_now();
        probe_countdown = JS_VM_STRONG_DBG_PROBE_PERIOD;
    } else {
        probe_countdown--;
    }
    return cached_verdict;
}
