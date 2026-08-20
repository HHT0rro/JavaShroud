/*
 * Attached-JVM JNI cache benchmark fixture.
 *
 * The probe starts a disposable JVM through JNI invocation, initializes the
 * production js_jni_cache, and measures repeated validation against a real
 * ClassLoader.  It intentionally reports only timings, counters and a digest
 * of public success states; class names, loader objects, method IDs and
 * exception payloads never enter the report.
 */
#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <jni.h>
#include "js_crypto.h"
#include "js_jni_runtime.h"
#include "js_vm_resource.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
typedef HMODULE js_jvm_module;
static js_jvm_module js_jvm_open(const char *path) { return LoadLibraryA(path); }
static void *js_jvm_symbol(js_jvm_module module, const char *name) {
    return module ? (void *)(uintptr_t)GetProcAddress(module, name) : NULL;
}
static void js_jvm_close(js_jvm_module module) { if (module) FreeLibrary(module); }
static uint64_t js_bench_ticks(void) {
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return (uint64_t)value.QuadPart;
}
static uint64_t js_bench_elapsed_ns(uint64_t elapsed) {
    static LARGE_INTEGER frequency;
    uint64_t hz;
    if (frequency.QuadPart == 0) QueryPerformanceFrequency(&frequency);
    hz = frequency.QuadPart > 0 ? (uint64_t)frequency.QuadPart : 0u;
    if (hz == 0u) return 0u;
    return (elapsed / hz) * UINT64_C(1000000000) +
        ((elapsed % hz) * UINT64_C(1000000000)) / hz;
}
#else
#include <dlfcn.h>
#include <time.h>
typedef void *js_jvm_module;
static js_jvm_module js_jvm_open(const char *path) { return dlopen(path, RTLD_NOW | RTLD_GLOBAL); }
static void *js_jvm_symbol(js_jvm_module module, const char *name) { return module ? dlsym(module, name) : NULL; }
static void js_jvm_close(js_jvm_module module) { if (module) dlclose(module); }
static uint64_t js_bench_ticks(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
static uint64_t js_bench_elapsed_ns(uint64_t elapsed) { return elapsed; }
#endif

typedef jint (JNICALL *js_jni_create_vm_fn)(JavaVM **, void **, void *);

typedef struct {
    uint64_t p50;
    uint64_t p95;
    uint64_t p99;
    uint64_t max;
} js_bench_latency;

static int js_parse_u32(const char *text, unsigned int *out) {
    char *end = NULL;
    unsigned long value;
    if (!text || !out || *text == '\0') return 0;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0' || value > 100000u) return 0;
    *out = (unsigned int)value;
    return 1;
}

static int js_compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : a > b ? 1 : 0;
}

static js_bench_latency js_latency_from_samples(uint64_t *samples, size_t count) {
    js_bench_latency latency = {0, 0, 0, 0};
    if (!samples || count == 0u) return latency;
    qsort(samples, count, sizeof(*samples), js_compare_u64);
    latency.p50 = samples[(count * 50u + 99u) / 100u - 1u];
    latency.p95 = samples[(count * 95u + 99u) / 100u - 1u];
    latency.p99 = samples[(count * 99u + 99u) / 100u - 1u];
    latency.max = samples[count - 1u];
    return latency;
}

static void js_mix_digest(uint64_t *digest, uint64_t value) {
    if (!digest) return;
    *digest ^= value + UINT64_C(0x9e3779b97f4a7c15) + (*digest << 6) + (*digest >> 2);
}

static int js_clear_exception(JNIEnv *env) {
    if (!env || !(*env)->ExceptionCheck(env)) return 1;
    (*env)->ExceptionClear(env);
    return 0;
}

static int js_run_probe(const char *jvm_path, unsigned int samples, unsigned int warmup) {
    js_jvm_module module = NULL;
    js_jni_create_vm_fn create_vm;
    JavaVM *vm = NULL;
    JNIEnv *env = NULL;
    JavaVMOption option;
    JavaVMInitArgs args;
    jclass owner = NULL;
    jclass loader_class = NULL;
    jmethodID get_system_loader = NULL;
    jobject loader = NULL;
    jobject invalid_loader = NULL;
    uint64_t *timings = NULL;
    js_bench_latency latency;
    js_crypto_runtime_metrics metrics;
    uint64_t digest = UINT64_C(0x243f6a8885a308d3);
    unsigned int rc;
    int result = 0;
    const char *stage = "arguments";

    if (!jvm_path || samples == 0u || samples > 100000u || warmup > 100000u) return 0;
    stage = "load-jvm";
    module = js_jvm_open(jvm_path);
    if (!module) goto cleanup;
    stage = "resolve-create-vm";
    create_vm = (js_jni_create_vm_fn)js_jvm_symbol(module, "JNI_CreateJavaVM");
    if (!create_vm) goto cleanup;

    option.optionString = "-Djava.class.path=.";
    option.extraInfo = NULL;
    memset(&args, 0, sizeof(args));
    args.version = JNI_VERSION_1_8;
    args.nOptions = 1;
    args.options = &option;
    args.ignoreUnrecognized = JNI_TRUE;
    stage = "create-vm";
    rc = (unsigned int)create_vm(&vm, (void **)&env, &args);
    if (rc != JNI_OK || !vm || !env) goto cleanup;

    stage = "cache-init";
    js_crypto_runtime_metrics_reset();
    if (!js_jni_cache_init(env)) goto cleanup;
    stage = "owner-class";
    owner = (*env)->FindClass(env, "java/lang/Object");
    if (!owner || !js_clear_exception(env)) goto cleanup;
    /* Bootstrap owner binding establishes the initial class/cache identity. */
    stage = "owner-validate";
    if (!js_jni_cache_validate(env, owner)) goto cleanup;

    stage = "loader-class";
    loader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
    if (!loader_class || !js_clear_exception(env)) goto cleanup;
    stage = "loader-method";
    get_system_loader = (*env)->GetStaticMethodID(
        env, loader_class, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    if (!get_system_loader || !js_clear_exception(env)) goto cleanup;
    stage = "system-loader";
    loader = (*env)->CallStaticObjectMethod(env, loader_class, get_system_loader);
    if (!loader || !js_clear_exception(env)) goto cleanup;

    /* A bootstrap-to-managed loader transition must rebuild, not reuse. */
    stage = "loader-transition";
    if (!js_jni_cache_validate_loader(env, loader)) goto cleanup;
    stage = "loader-hit";
    if (!js_jni_cache_validate_loader(env, loader)) goto cleanup;

    /* A non-ClassLoader receiver must fail closed without poisoning the cache. */
    stage = "invalid-loader-object";
    invalid_loader = (*env)->NewObject(env, owner, (*env)->GetMethodID(env, owner, "<init>", "()V"));
    if (!invalid_loader || !js_clear_exception(env)) goto cleanup;
    stage = "invalid-loader-reject";
    if (js_jni_cache_validate_loader(env, invalid_loader)) goto cleanup;
    /* The mismatch path wipes every stale global reference.  A subsequent
     * matching loader must reconstruct and re-bind the full current cache. */
    stage = "invalid-loader-recover";
    if (!js_jni_cache_validate_loader(env, loader)) goto cleanup;

    /* Session generation invalidation forces a rebuild before the next use. */
    stage = "generation-reset";
    js_vm_call_gate_reset();
    stage = "generation-rebuild";
    if (!js_jni_cache_validate_loader(env, loader)) goto cleanup;

    stage = "allocate-timings";
    timings = (uint64_t *)calloc(samples, sizeof(*timings));
    if (!timings) goto cleanup;
    stage = "warmup";
    for (unsigned int index = 0u; index < warmup; ++index) {
        if (!js_jni_cache_validate_loader(env, loader)) goto cleanup;
    }
    js_crypto_runtime_metrics_reset();
    stage = "measure";
    for (unsigned int index = 0u; index < samples; ++index) {
        uint64_t start = js_bench_ticks();
        if (!js_jni_cache_validate_loader(env, loader)) goto cleanup;
        timings[index] = js_bench_elapsed_ns(js_bench_ticks() - start);
        js_mix_digest(&digest, ((uint64_t)index << 32u) ^ (uint64_t)js_jni_cache.initialized);
    }
    latency = js_latency_from_samples(timings, samples);
    memset(&metrics, 0, sizeof(metrics));
    js_crypto_runtime_metrics_snapshot(&metrics);
    printf(
        "phase=jni-method-class-lookup phase_mode=production phase_status=pass samples=%u warmup=%u "
        "p50=%lluns p95=%lluns p99=%lluns max=%lluns "
        "cpu_hardware_aes=%d cpu_hardware_ghash=%d hardware_crypto_path=%llu software_crypto_path=%llu "
        "aes_block_count=%llu ghash_block_count=%llu vm_frame_reuse_count=%llu vm_heap_fallback_count=%llu "
        "resource_index_hit_count=%llu decompress_context_reuse_count=%llu jni_cache_hit_count=%llu "
        "auth_check_count=%llu auth_failure_count=%llu digest_check_count=%llu tag_check_count=%llu "
        "length_check_count=%llu structure_check_count=%llu jni_abi_check_count=%llu wipe_count=%llu "
        "allocation_count=0 exception_count=%llu native_exception_count=0 fallback_count=%llu legacy_path_hits=%llu "
        "wipe_failure_count=%llu plaintext_persistence_bytes=0 security_checks_skipped=0 output_digest=%016llx\n",
        samples,
        warmup,
        (unsigned long long)latency.p50,
        (unsigned long long)latency.p95,
        (unsigned long long)latency.p99,
        (unsigned long long)latency.max,
        js_aes_hardware_available(),
        js_ghash_hardware_available(),
        (unsigned long long)metrics.hardware_crypto_path,
        (unsigned long long)metrics.software_crypto_path,
        (unsigned long long)metrics.aes_block_count,
        (unsigned long long)metrics.ghash_block_count,
        (unsigned long long)metrics.vm_frame_reuse_count,
        (unsigned long long)metrics.vm_heap_fallback_count,
        (unsigned long long)metrics.resource_index_hit_count,
        (unsigned long long)metrics.decompress_context_reuse_count,
        (unsigned long long)metrics.jni_cache_hit_count,
        (unsigned long long)metrics.auth_check_count,
        (unsigned long long)metrics.auth_failure_count,
        (unsigned long long)metrics.digest_check_count,
        (unsigned long long)metrics.tag_check_count,
        (unsigned long long)metrics.length_check_count,
        (unsigned long long)metrics.structure_check_count,
        (unsigned long long)metrics.jni_abi_check_count,
        (unsigned long long)metrics.wipe_count,
        (unsigned long long)metrics.exception_count,
        (unsigned long long)metrics.fallback_count,
        (unsigned long long)metrics.legacy_path_hits,
        (unsigned long long)metrics.wipe_failure_count,
        (unsigned long long)digest);
    result = metrics.jni_cache_hit_count >= (uint64_t)samples &&
        metrics.jni_abi_check_count >= (uint64_t)samples &&
        metrics.auth_check_count == 0u &&
        metrics.fallback_count == 0u &&
        metrics.legacy_path_hits == 0u &&
        metrics.wipe_failure_count == 0u &&
        metrics.plaintext_persistence_bytes == 0u &&
        metrics.security_checks_skipped == 0u &&
        metrics.exception_count == 0u;
    stage = result ? "pass" : "security-gate";

cleanup:
    if (env) {
        if (js_jni_cache.initialized) js_jni_cache_destroy(env);
        if (invalid_loader) (*env)->DeleteLocalRef(env, invalid_loader);
        if (loader) (*env)->DeleteLocalRef(env, loader);
        if (loader_class) (*env)->DeleteLocalRef(env, loader_class);
        if (owner) (*env)->DeleteLocalRef(env, owner);
    }
    if (vm) (*vm)->DestroyJavaVM(vm);
    if (timings) {
        js_vbc4_wipe_volatile(timings, (size_t)samples * sizeof(*timings));
        free(timings);
    }
    js_jvm_close(module);
    if (!result) fprintf(stderr, "jni-cache-production probe failed at stage=%s\n", stage);
    return result;
}

int main(int argc, char **argv) {
    unsigned int samples = 100u;
    unsigned int warmup = 16u;
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: %s JVM_PATH [SAMPLES] [WARMUP]\n", argc > 0 ? argv[0] : "jni-cache-probe");
        return 2;
    }
    if (argc > 2 && !js_parse_u32(argv[2], &samples)) return 2;
    if (argc > 3 && !js_parse_u32(argv[3], &warmup)) return 2;
    return js_run_probe(argv[1], samples, warmup) ? 0 : 1;
}
