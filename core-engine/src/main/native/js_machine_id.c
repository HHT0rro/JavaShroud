#include "js_machine_id.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdbool.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/types.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

static int js_machine_id_trim_and_lower(char *out, size_t out_len) {
    if (!out || out_len == 0) return 0;
    size_t start = 0;
    size_t end = strlen(out);
    while (start < end && isspace((unsigned char)out[start])) start++;
    while (end > start && isspace((unsigned char)out[end - 1])) end--;
    size_t len = end - start;
    if (len == 0 || len >= out_len) return 0;
    for (size_t i = 0; i < len; i++) {
        out[i] = (char)tolower((unsigned char)out[start + i]);
    }
    out[len] = '\0';
    return (int)len;
}

#if defined(_WIN32)
int js_machine_id(char *out, size_t out_len) {
    if (!out || out_len < 64) return 0;
    DWORD size = (DWORD)out_len;
    LSTATUS status = RegGetValueA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        "MachineGuid",
        RRF_RT_REG_SZ,
        NULL,
        out,
        &size);
    if (status != ERROR_SUCCESS || size == 0 || (size_t)size >= out_len) return 0;
    out[size] = '\0';
    return js_machine_id_trim_and_lower(out, out_len);
}
#elif defined(__linux__)
int js_machine_id(char *out, size_t out_len) {
    if (!out || out_len < 64) return 0;
    const char *paths[] = { "/etc/machine-id", "/var/lib/dbus/machine-id" };
    for (size_t p = 0; p < sizeof(paths) / sizeof(paths[0]); p++) {
        FILE *f = fopen(paths[p], "r");
        if (!f) continue;
        char *r = fgets(out, (int)out_len, f);
        fclose(f);
        if (r) {
            int len = js_machine_id_trim_and_lower(out, out_len);
            if (len > 0) return len;
        }
    }
    return 0;
}
#elif defined(__APPLE__)
int js_machine_id(char *out, size_t out_len) {
    if (!out || out_len < 64) return 0;
    size_t len = out_len;
    if (sysctlbyname("kern.hostuuid", out, &len, NULL, 0) != 0 || len == 0 || len >= out_len) return 0;
    out[len] = '\0';
    return js_machine_id_trim_and_lower(out, out_len);
}
#else
int js_machine_id(char *out, size_t out_len) {
    (void)out;
    (void)out_len;
    return 0;
}
#endif
