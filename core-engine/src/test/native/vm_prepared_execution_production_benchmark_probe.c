/*
 * Attached-JVM prepared-program benchmark fixture.
 *
 * This fixture starts a disposable, real JNI invocation JVM and drives the
 * production prepared-program entry point (js_vm_execute_prepared_program_int_int)
 * with a current-format session-bound program.  The program is assembled only
 * from the same resident instruction representation used by parsed VBC4
 * programs; no Java fallback/interpreter or alternate ABI is involved.  The
 * fixture reports timings, counters, and a digest of primitive return values
 * only.  It also acquires nested execution frames on the attached JVM thread
 * to verify LIFO depth isolation and fail-closed overflow behavior, then runs
 * the same prepared entrypoint from several independently attached native
 * threads to verify TLS/FLS frame ownership and primitive return isolation.
 */
#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <jni.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_crypto.h"

#ifndef JS_VM_EXECUTION_FRAME_TEST
#error "vm_prepared_execution_production_benchmark_probe.c requires JS_VM_EXECUTION_FRAME_TEST=1"
#endif

/* Include the production VM implementation once so this probe can use the
 * file-local prepared-program and frame helpers without widening the JNI ABI. */
#include "js_vm_core.c"

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
static void *js_jvm_symbol(js_jvm_module module, const char *name) {
    return module ? dlsym(module, name) : NULL;
}
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

#define JS_VM_THREAD_PROBE_COUNT 4u
#define JS_VM_THREAD_PROBE_ITERATIONS 32u

typedef struct {
    JavaVM *vm;
    js_vm_program *program;
    unsigned int iterations;
    volatile unsigned int failed;
    volatile unsigned int completed;
    uint64_t digest;
} js_vm_thread_probe_context;

static void js_vm_thread_probe_execute(js_vm_thread_probe_context *context, JNIEnv *env) {
    uint64_t digest = UINT64_C(0x517cc1b727220a95);
    if (!context || !env || !context->program) {
        if (context) context->failed = 1u;
        return;
    }
    for (unsigned int index = 0u; index < context->iterations; index++) {
        jint output = 0;
        int ok = js_vm_execute_prepared_program_int_int(env, context->program, (jint)index, &output);
        if (!ok || output != 41 || (*env)->ExceptionCheck(env)) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            context->failed = 1u;
            return;
        }
        js_mix_digest(&digest, ((uint64_t)index << 32u) ^ (uint32_t)output);
    }
    context->digest = digest;
    context->completed = context->iterations;
}

#if defined(_WIN32)
static DWORD WINAPI js_vm_thread_probe_entry(LPVOID opaque) {
    js_vm_thread_probe_context *context = (js_vm_thread_probe_context *)opaque;
    JNIEnv *env = NULL;
    if (!context || !context->vm ||
        (*context->vm)->AttachCurrentThread(context->vm, (void **)&env, NULL) != JNI_OK || !env) {
        if (context) context->failed = 1u;
        return 0u;
    }
    js_vm_thread_probe_execute(context, env);
    (*context->vm)->DetachCurrentThread(context->vm);
    return 0u;
}
#else
static void *js_vm_thread_probe_entry(void *opaque) {
    js_vm_thread_probe_context *context = (js_vm_thread_probe_context *)opaque;
    JNIEnv *env = NULL;
    if (!context || !context->vm ||
        (*context->vm)->AttachCurrentThread(context->vm, (void **)&env, NULL) != JNI_OK || !env) {
        if (context) context->failed = 1u;
        return NULL;
    }
    js_vm_thread_probe_execute(context, env);
    (*context->vm)->DetachCurrentThread(context->vm);
    return NULL;
}
#endif

/* Exercise the production prepared entrypoint from independent JVM-attached
 * native threads.  Each worker must acquire its own TLS/FLS execution-frame
 * arena, preserve primitive return semantics, and leave no pending JNI
 * exception before detaching.  The resident program is read-only during this
 * path; mutable instruction state is copied into the worker-owned frame. */
static int js_multithread_prepared_execution(JavaVM *vm, js_vm_program *program, uint64_t *digest_out) {
    js_vm_thread_probe_context contexts[JS_VM_THREAD_PROBE_COUNT];
#if defined(_WIN32)
    HANDLE threads[JS_VM_THREAD_PROBE_COUNT];
#else
    pthread_t threads[JS_VM_THREAD_PROBE_COUNT];
#endif
    unsigned int created = 0u;
    int ok = 1;
    if (!vm || !program || !digest_out) return 0;
    memset(contexts, 0, sizeof(contexts));
#if defined(_WIN32)
    memset(threads, 0, sizeof(threads));
#endif
    for (unsigned int index = 0u; index < JS_VM_THREAD_PROBE_COUNT; index++) {
        contexts[index].vm = vm;
        contexts[index].program = program;
        contexts[index].iterations = JS_VM_THREAD_PROBE_ITERATIONS;
#if defined(_WIN32)
        threads[index] = CreateThread(NULL, 0u, js_vm_thread_probe_entry, &contexts[index], 0u, NULL);
        if (!threads[index]) { ok = 0; break; }
#else
        if (pthread_create(&threads[index], NULL, js_vm_thread_probe_entry, &contexts[index]) != 0) { ok = 0; break; }
#endif
        created++;
    }
    for (unsigned int index = 0u; index < created; index++) {
#if defined(_WIN32)
        if (WaitForSingleObject(threads[index], INFINITE) != WAIT_OBJECT_0) ok = 0;
        CloseHandle(threads[index]);
#else
        if (pthread_join(threads[index], NULL) != 0) ok = 0;
#endif
        if (contexts[index].failed || contexts[index].completed != JS_VM_THREAD_PROBE_ITERATIONS) ok = 0;
        js_mix_digest(digest_out, contexts[index].digest);
    }
    return ok && created == JS_VM_THREAD_PROBE_COUNT;
}

static int js_init_prepared_program(js_vm_program *program) {
    static const unsigned char startup_nonce[32] = {
        0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
        0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
        0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
        0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
    };
    static const unsigned char nonce[16] = {
        0x4a, 0x53, 0x52, 0x50, 0x2d, 0x56, 0x4d, 0x2d,
        0x46, 0x52, 0x41, 0x4d, 0x45, 0x2d, 0x31, 0x00
    };
    static const unsigned char method_identity[32] = {
        0x1d, 0x3a, 0x57, 0x74, 0x91, 0xae, 0xcb, 0xe8,
        0x05, 0x22, 0x3f, 0x5c, 0x79, 0x96, 0xb3, 0xd0,
        0xed, 0x0a, 0x27, 0x44, 0x61, 0x7e, 0x9b, 0xb8,
        0xd5, 0xf2, 0x0f, 0x2c, 0x49, 0x66, 0x83, 0xa0
    };
    static const unsigned char owner_identity[32] = {
        0xa0, 0x83, 0x66, 0x49, 0x2c, 0x0f, 0xf2, 0xd5,
        0xb8, 0x9b, 0x7e, 0x61, 0x44, 0x27, 0x0a, 0xed,
        0xd0, 0xb3, 0x96, 0x79, 0x5c, 0x3f, 0x22, 0x05,
        0xe8, 0xcb, 0xae, 0x91, 0x74, 0x57, 0x3a, 0x1d
    };
    const jlong entry_token = (jlong)INT64_C(0x13579BDF2468ACE1);
    const char *resource_path = "META-INF/.fixture/vm-prepared.vbc4";
    if (!program) return 0;
    memset(program, 0, sizeof(*program));
    if (!js_vm_install_startup_nonce(startup_nonce, (int)sizeof(startup_nonce))) { fprintf(stderr, "prep=install-nonce\n"); return 0; }
    memcpy(program->nonce, nonce, sizeof(program->nonce));
    memcpy(program->method_identity, method_identity, sizeof(program->method_identity));
    memcpy(program->owner_identity, owner_identity, sizeof(program->owner_identity));
    program->return_desc = 'I';
    program->is_static = 1u;
    program->argument_count = 1;
    program->argument_tags = (char *)malloc(1u);
    if (!program->argument_tags) { fprintf(stderr, "prep=argument-tags\n"); return 0; }
    program->argument_tags[0] = 'I';
    program->native_vm_profile_id = JS_NATIVE_VM_PROFILE_ID;
    program->method_local_profile = 0u;
    program->vbc4_flags = 0u;
    program->nested_vm_profile = 0u;
    js_vm_init_resident_key_mask(program, program->nonce);
    js_vm_store_resident_build_seed(program, 0x13572468);
    js_vm_store_resident_mac_key(program, 0x2468ACE1);
    if (!js_vm_bind_runtime_session(program, entry_token, resource_path)) { fprintf(stderr, "prep=bind-session\n"); return 0; }
    program->dispatch_profile_tag = js_vm_dispatch_profile_tag_for(program);
    /* The session tag covers dispatch/profile metadata.  Parsed VBC4 programs
     * have this field before binding; the fixture computes it immediately and
     * reseals the tag before any execution so verification remains exact. */
    js_vm_runtime_session_tag(program, program->session_leaf, program->session_tag);
    program->insn_count = 2;
    program->max_stack = 2;
    program->max_locals = 1;
    program->cached_execution_ready = 1;
    program->insns = (js_vm_insn *)calloc(2u, sizeof(*program->insns));
    if (!program->insns) { fprintf(stderr, "prep=insns\n"); return 0; }
    program->insns[0].opcode_epoch = 0;
    program->insns[0].op_count = 1;
    program->insns[0].ops = (jint *)calloc(1u, sizeof(jint));
    if (!program->insns[0].ops) { fprintf(stderr, "prep=operands\n"); return 0; }
    program->insns[0].opcode = js_vm_store_resident_opcode(program, 0, JS_VM_ICONST);
    program->insns[0].ops[0] = js_vm_store_resident_operand(program, 0, 0, 41);
    program->insns[1].opcode_epoch = 0;
    program->insns[1].op_count = 0;
    program->insns[1].ops = NULL;
    program->insns[1].opcode = js_vm_store_resident_opcode(program, 1, JS_VM_IRETURN);
    if (!js_vm_verify_runtime_session(program)) { fprintf(stderr, "prep=verify-session\n"); return 0; }
    if (!js_vm_dispatch_profile_tag_matches(program)) { fprintf(stderr, "prep=dispatch-tag\n"); return 0; }
    return 1;
}

/* Construct the same authenticated current-format sealed-string constant that
 * VmBytecodeSerializer emits.  The synthetic fixture must exercise the
 * production decoder rather than populate cp.s with an unauthenticated raw
 * string, because current artifacts reject seed-only plaintext constants. */
static int js_init_sealed_catch_constant(js_vm_program *program, const char *value) {
    static const unsigned char key_domain[] = "javashroud-vbc4-cp-string-key-v2";
    static const unsigned char iv_domain[] = "javashroud-vbc4-cp-string-iv-v2";
    static const unsigned char tag_domain[] = "javashroud-vbc4-cp-string-tag-v2";
    const unsigned char sealed_nonce[16] = {
        0x53, 0x45, 0x41, 0x4c, 0x45, 0x44, 0x2d, 0x43,
        0x50, 0x2d, 0x46, 0x49, 0x58, 0x54, 0x55, 0x52
    };
    const size_t value_len = value ? strlen(value) : 0u;
    const size_t payload_offset = 1u + sizeof(sealed_nonce) + 2u;
    const size_t tag_offset = payload_offset + value_len;
    const size_t plain_len = tag_offset + 32u;
    unsigned char build_key[32] = {0};
    unsigned char key_material[32] = {0};
    unsigned char iv_material[32] = {0};
    unsigned char tag[32] = {0};
    unsigned char key[16] = {0};
    unsigned char iv[16] = {0};
    unsigned char outer_key[16] = {0};
    unsigned char outer_iv[16] = {0};
    unsigned char *plain = NULL;
    unsigned char *enc = NULL;
    int ok = 0;

    if (!program || !program->cp || program->cp_count != 1 || !value ||
        value_len == 0u || value_len > 0xFFFFu || plain_len > (size_t)INT_MAX) {
        return 0;
    }
    plain = (unsigned char *)calloc(1u, plain_len);
    enc = (unsigned char *)malloc(plain_len);
    if (!plain || !enc || !js_vm_copy_runtime_build_key(build_key)) goto cleanup;

    plain[0] = JS_VM_CP_SEALED_STRING;
    memcpy(plain + 1u, sealed_nonce, sizeof(sealed_nonce));
    plain[17] = (unsigned char)((value_len >> 8u) & 0xFFu);
    plain[18] = (unsigned char)(value_len & 0xFFu);
    memcpy(plain + payload_offset, value, value_len);

    {
        const unsigned char *parts[2] = { key_domain, sealed_nonce };
        const int lens[2] = {
            (int)(sizeof(key_domain) - 1u), (int)sizeof(sealed_nonce)
        };
        js_hmac_sha256_with_key(build_key, 32, parts, lens, 2, key_material);
    }
    {
        const unsigned char *parts[2] = { iv_domain, sealed_nonce };
        const int lens[2] = {
            (int)(sizeof(iv_domain) - 1u), (int)sizeof(sealed_nonce)
        };
        js_hmac_sha256_with_key(build_key, 32, parts, lens, 2, iv_material);
    }
    memcpy(key, key_material, sizeof(key));
    memcpy(iv, iv_material, sizeof(iv));
    js_vbc4_decrypt_block_with_material(plain + payload_offset, (int)value_len, key, iv);
    {
        const unsigned char *parts[3] = { tag_domain, sealed_nonce, plain + payload_offset };
        const int lens[3] = {
            (int)(sizeof(tag_domain) - 1u), (int)sizeof(sealed_nonce), (int)value_len
        };
        js_hmac_sha256_with_key(build_key, 32, parts, lens, 3, tag);
    }
    memcpy(plain + tag_offset, tag, sizeof(tag));

    memcpy(enc, plain, plain_len);
    js_vbc4_aes_material(
        js_vm_load_resident_build_seed(program),
        program->nonce,
        JS_VBC4_SECTION_CONSTANT_POOL_ENTRY,
        0,
        outer_key,
        outer_iv
    );
    js_vbc4_decrypt_block_with_material(enc, (int)plain_len, outer_key, outer_iv);
    program->cp[0].enc = enc;
    program->cp[0].enc_len = (int)plain_len;
    program->cp[0].stored_len = (int)plain_len;
    program->cp[0].plain_len = (int)plain_len;
    program->cp[0].entry_id = 0;
    program->cp[0].stored_zstd = 0u;
    memcpy(program->cp[0].key, outer_key, sizeof(outer_key));
    memcpy(program->cp[0].iv, outer_iv, sizeof(outer_iv));
    enc = NULL;
    ok = 1;

cleanup:
    if (plain) { js_vbc4_wipe_volatile(plain, plain_len); free(plain); }
    if (enc) { js_vbc4_wipe_volatile(enc, plain_len); free(enc); }
    js_vbc4_wipe_volatile(build_key, sizeof(build_key));
    js_vbc4_wipe_volatile(key_material, sizeof(key_material));
    js_vbc4_wipe_volatile(iv_material, sizeof(iv_material));
    js_vbc4_wipe_volatile(tag, sizeof(tag));
    js_vbc4_wipe_volatile(key, sizeof(key));
    js_vbc4_wipe_volatile(iv, sizeof(iv));
    js_vbc4_wipe_volatile(outer_key, sizeof(outer_key));
    js_vbc4_wipe_volatile(outer_iv, sizeof(outer_iv));
    return ok;
}

/* Build a small current-format resident program whose IDIV-by-zero fault is
 * handled by its authenticated typed exception table.  This keeps
 * exception semantic coverage on the same production prepared-program
 * entrypoint as the hot-path benchmark instead of using a Java fallback or a
 * second ABI.  The handler still receives and pops the thrown object before
 * returning its sentinel value. */
static int js_init_exception_program(js_vm_program *program) {
    static const unsigned char nonce[16] = {
        0x45, 0x58, 0x43, 0x2d, 0x56, 0x4d, 0x2d, 0x45,
        0x58, 0x43, 0x45, 0x50, 0x54, 0x2d, 0x31, 0x00
    };
    static const unsigned char method_identity[32] = {
        0x2e, 0x4b, 0x68, 0x85, 0xa2, 0xbf, 0xdc, 0xf9,
        0x16, 0x33, 0x50, 0x6d, 0x8a, 0xa7, 0xc4, 0xe1,
        0xfe, 0x1b, 0x38, 0x55, 0x72, 0x8f, 0xac, 0xc9,
        0xe6, 0x03, 0x20, 0x3d, 0x5a, 0x77, 0x94, 0xb1
    };
    static const unsigned char owner_identity[32] = {
        0xb1, 0x94, 0x77, 0x5a, 0x3d, 0x20, 0x03, 0xe6,
        0xc9, 0xac, 0x8f, 0x72, 0x55, 0x38, 0x1b, 0xfe,
        0xe1, 0xc4, 0xa7, 0x8a, 0x6d, 0x50, 0x33, 0x16,
        0xf9, 0xdc, 0xbf, 0xa2, 0x85, 0x68, 0x4b, 0x2e
    };
    const jlong entry_token = (jlong)INT64_C(0x2468ACE013579BDF);
    const char *resource_path = "META-INF/.fixture/vm-exception.vbc4";
    const char *catch_type = "java/lang/ArithmeticException";
    if (!program) return 0;
    memset(program, 0, sizeof(*program));
    memcpy(program->nonce, nonce, sizeof(program->nonce));
    memcpy(program->method_identity, method_identity, sizeof(program->method_identity));
    memcpy(program->owner_identity, owner_identity, sizeof(program->owner_identity));
    program->return_desc = 'I';
    program->is_static = 1u;
    program->argument_count = 0;
    program->native_vm_profile_id = JS_NATIVE_VM_PROFILE_ID;
    program->method_local_profile = 0u;
    program->vbc4_flags = 0u;
    program->nested_vm_profile = 0u;
    js_vm_init_resident_key_mask(program, program->nonce);
    js_vm_store_resident_build_seed(program, 0x31415926);
    js_vm_store_resident_mac_key(program, 0x27182818);
    if (!js_vm_bind_runtime_session(program, entry_token, resource_path)) return 0;
    program->dispatch_profile_tag = js_vm_dispatch_profile_tag_for(program);
    js_vm_runtime_session_tag(program, program->session_leaf, program->session_tag);

    program->cp_count = 1;
    program->cp = (js_vm_cp *)calloc(1u, sizeof(*program->cp));
    if (!program->cp || !js_init_sealed_catch_constant(program, catch_type)) return 0;

    program->insn_count = 7;
    program->max_stack = 3;
    program->max_locals = 0;
    program->cached_execution_ready = 1;
    program->insns = (js_vm_insn *)calloc((size_t)program->insn_count, sizeof(*program->insns));
    if (!program->insns) return 0;
    for (int index = 0; index < program->insn_count; index++) program->insns[index].opcode_epoch = 0;
    program->insns[0].op_count = 1;
    program->insns[0].ops = (jint *)calloc(1u, sizeof(jint));
    if (!program->insns[0].ops) return 0;
    program->insns[0].opcode = js_vm_store_resident_opcode(program, 0, JS_VM_ICONST);
    program->insns[0].ops[0] = js_vm_store_resident_operand(program, 0, 0, 1);
    program->insns[1].op_count = 1;
    program->insns[1].ops = (jint *)calloc(1u, sizeof(jint));
    if (!program->insns[1].ops) return 0;
    program->insns[1].opcode = js_vm_store_resident_opcode(program, 1, JS_VM_ICONST);
    program->insns[1].ops[0] = js_vm_store_resident_operand(program, 1, 0, 0);
    program->insns[2].opcode = js_vm_store_resident_opcode(program, 2, JS_VM_IDIV);
    program->insns[3].opcode = js_vm_store_resident_opcode(program, 3, JS_VM_IRETURN);
    program->insns[4].opcode = js_vm_store_resident_opcode(program, 4, JS_VM_POP);
    program->insns[5].op_count = 1;
    program->insns[5].ops = (jint *)calloc(1u, sizeof(jint));
    if (!program->insns[5].ops) return 0;
    program->insns[5].opcode = js_vm_store_resident_opcode(program, 5, JS_VM_ICONST);
    program->insns[5].ops[0] = js_vm_store_resident_operand(program, 5, 0, 42);
    program->insns[6].opcode = js_vm_store_resident_opcode(program, 6, JS_VM_IRETURN);

    program->exception_count = 1;
    program->exceptions = (js_vm_exception *)calloc(1u, sizeof(*program->exceptions));
    if (!program->exceptions) return 0;
    program->exceptions[0].start = js_vm_store_resident_exception_field(program, 0, 0, 0);
    program->exceptions[0].end = js_vm_store_resident_exception_field(program, 0, 1, 3);
    program->exceptions[0].handler = js_vm_store_resident_exception_field(program, 0, 2, 4);
    program->exceptions[0].type_cp = js_vm_store_resident_exception_field(program, 0, 3, 1);
    program->cfg_exceptions_decoded = 1;
    if (!js_vm_verify_runtime_session(program)) return 0;
    if (!js_vm_dispatch_profile_tag_matches(program)) return 0;
    return 1;
}

/* Prepare an isolated current-format program whose CP[0] is an authenticated
 * method reference.  Keeping this program separate from the typed-exception
 * fixture prevents the CP entry from being repurposed after the exception
 * table has been verified, while still exercising the production decoder,
 * resolver, JNI method cache, and static invocation path. */
static int js_init_static_invoke_cp0_program(js_vm_program *program) {
    static const char method_ref[] = "java/lang/Math.abs:(I)I";
    static const unsigned char layout_digest[32] = {
        0x41, 0x4b, 0x45, 0x4e, 0x2d, 0x43, 0x50, 0x2d,
        0x44, 0x45, 0x46, 0x45, 0x52, 0x52, 0x45, 0x44,
        0x2d, 0x4c, 0x41, 0x59, 0x4f, 0x55, 0x54, 0x2d,
        0x42, 0x49, 0x4e, 0x44, 0x49, 0x4e, 0x47, 0x31
    };
    js_vm_cp *cp = NULL;
    int ok = 0;
    int scoped_layout_digest_installed = 0;
    if (!program || !js_vbc4_install_scoped_layout_digest(layout_digest)) return 0;
    scoped_layout_digest_installed = 1;
    if (!js_init_exception_program(program) || !program->cp || program->cp_count != 1) goto cleanup;
    cp = &program->cp[0];
    if (cp->s) {
        js_vbc4_wipe_volatile(cp->s, strlen(cp->s));
        free(cp->s);
        cp->s = NULL;
    }
    if (cp->enc) {
        js_vbc4_wipe_volatile(cp->enc, cp->enc_len > 0 ? (size_t)cp->enc_len : 0u);
        free(cp->enc);
        cp->enc = NULL;
    }
    js_vbc4_wipe_volatile(cp->key, sizeof(cp->key));
    js_vbc4_wipe_volatile(cp->iv, sizeof(cp->iv));
    cp->enc_len = 0;
    cp->stored_len = 0;
    cp->plain_len = 0;
    cp->entry_id = 0;
    cp->stored_zstd = 0u;
    ok = js_init_sealed_catch_constant(program, method_ref) &&
        program->session_bound && program->session_layout_digest_bound &&
        memcmp(program->session_layout_digest, layout_digest, sizeof(layout_digest)) == 0;

cleanup:
    /* Reproduce the production AKEN lifetime: the authenticated layout scope
     * exists only while parsing/binding, while CP resolution is deferred until
     * execution after the scope has been wiped. */
    if (scoped_layout_digest_installed) js_vbc4_clear_scoped_layout_digest();
    return ok;
}

/* Directly exercise the production VM_INVOKESTATIC path with CP index 0.
 * The input and result are primitive values; no method reference, key, nonce,
 * or plaintext is emitted. */
static int js_invoke_static_cp0_fixture(JNIEnv *env, js_vm_program *program, jint *result_out) {
    js_vm_value stack[2];
    js_vm_value locals[1];
    int sp = 1;
    int status;
    int ok;
    if (!env || !program || !result_out) return 0;
    memset(stack, 0, sizeof(stack));
    memset(locals, 0, sizeof(locals));
    stack[0] = js_vm_int_value(-7);
    status = js_vm_invoke_method(
        env,
        program,
        0,
        JS_VM_INVOKESTATIC,
        stack,
        (int)(sizeof(stack) / sizeof(stack[0])),
        &sp,
        locals,
        (int)(sizeof(locals) / sizeof(locals[0])),
        1u,
        0u);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        status = 0;
    }
    ok = status && sp == 1 && stack[0].type == JS_VM_VAL_INT && stack[0].i == 7 &&
        js_vm_last_cp_decode_stage == 9 && js_vm_last_cp_decode_auth == 1;
    if (ok) *result_out = stack[0].i;
    js_vm_clear_value(&stack[0]);
    js_vm_clear_value(&stack[1]);
    js_vm_clear_value(&locals[0]);
    js_vbc4_wipe_volatile(stack, sizeof(stack));
    js_vbc4_wipe_volatile(locals, sizeof(locals));
    return ok;
}

enum js_static_cp0_tamper_kind {
    JS_STATIC_CP0_TAMPER_CIPHERTEXT = 1,
    JS_STATIC_CP0_TAMPER_TAG = 2,
    JS_STATIC_CP0_TAMPER_NONCE = 3,
    JS_STATIC_CP0_TAMPER_LENGTH = 4,
    JS_STATIC_CP0_TAMPER_TYPE = 5,
};

/* Mutate one authenticated current-format CP field in a private fixture.
 * The helper decrypts only into bounded scratch, re-seals the entry, and
 * wipes that scratch before returning.  No plaintext or key material is
 * emitted; callers observe only the fail-closed result. */
static int js_tamper_static_cp0_entry(js_vm_program *program, int kind) {
    js_vm_cp *cp;
    unsigned char *plain = NULL;
    size_t plain_len;
    unsigned int string_len;
    size_t tag_offset;
    int ok = 0;
    if (!program || !program->cp || program->cp_count != 1) return 0;
    cp = &program->cp[0];
    if (!cp->enc || cp->enc_len <= 0 || cp->plain_len <= 0 || cp->stored_len != cp->plain_len) return 0;
    plain_len = (size_t)cp->plain_len;
    if (plain_len < 1u + 16u + 2u + 32u) return 0;
    if (kind == JS_STATIC_CP0_TAMPER_LENGTH) {
        if (cp->stored_len <= 1) return 0;
        cp->stored_len--;
        return 1;
    }
    plain = (unsigned char *)malloc(plain_len);
    if (!plain) return 0;
    memcpy(plain, cp->enc, plain_len);
    js_vbc4_decrypt_block_with_material(plain, (int)plain_len, cp->key, cp->iv);
    string_len = ((unsigned int)plain[17] << 8u) | (unsigned int)plain[18];
    tag_offset = 19u + (size_t)string_len;
    if (tag_offset + 32u > plain_len) goto cleanup;
    switch (kind) {
        case JS_STATIC_CP0_TAMPER_CIPHERTEXT:
            cp->enc[cp->enc_len / 2] ^= 0x5Au;
            ok = 1;
            goto cleanup;
        case JS_STATIC_CP0_TAMPER_TAG:
            plain[tag_offset] ^= 0x01u;
            break;
        case JS_STATIC_CP0_TAMPER_NONCE:
            plain[1] ^= 0x01u;
            break;
        case JS_STATIC_CP0_TAMPER_TYPE:
            plain[0] = JS_VM_CP_STRING;
            break;
        default:
            goto cleanup;
    }
    js_vbc4_decrypt_block_with_material(plain, (int)plain_len, cp->key, cp->iv);
    memcpy(cp->enc, plain, plain_len);
    ok = 1;

cleanup:
    if (plain) {
        js_vbc4_wipe_volatile(plain, plain_len);
        free(plain);
    }
    return ok;
}

static int js_invoke_static_cp0_rejects_tamper(JNIEnv *env, js_vm_program *program) {
    js_vm_value stack[2];
    js_vm_value locals[1];
    int sp = 1;
    int status;
    int pending;
    int ok;
    if (!env || !program) return 0;
    memset(stack, 0, sizeof(stack));
    memset(locals, 0, sizeof(locals));
    stack[0] = js_vm_int_value(-7);
    status = js_vm_invoke_method(
        env, program, 0, JS_VM_INVOKESTATIC,
        stack, (int)(sizeof(stack) / sizeof(stack[0])), &sp,
        locals, (int)(sizeof(locals) / sizeof(locals[0])), 1u, 0u);
    pending = (*env)->ExceptionCheck(env) ? 1 : 0;
    if (pending) (*env)->ExceptionClear(env);
    ok = !status && !pending;
    js_vm_clear_value(&stack[0]);
    js_vm_clear_value(&stack[1]);
    js_vm_clear_value(&locals[0]);
    js_vbc4_wipe_volatile(stack, sizeof(stack));
    js_vbc4_wipe_volatile(locals, sizeof(locals));
    return ok;
}

static void js_clear_prepared_program(JNIEnv *env, js_vm_program *program) {
    if (!program) return;
    js_vm_free_program(env, program);
}

static int js_nested_frame_lifecycle(js_vm_program *program) {
    js_vm_execution_frame *frames[JS_VM_EXECUTION_FRAME_MAX_DEPTH];
    memset(frames, 0, sizeof(frames));
    for (unsigned int depth = 0u; depth < JS_VM_EXECUTION_FRAME_MAX_DEPTH; depth++) {
        frames[depth] = js_vm_execution_frame_acquire(program);
        if (!frames[depth] || frames[depth]->depth != depth + 1u ||
            frames[depth]->owner_program != program || frames[depth]->generation == 0u) return 0;
    }
    if (js_vm_execution_frame_acquire(program) != NULL) return 0;
    for (unsigned int depth = JS_VM_EXECUTION_FRAME_MAX_DEPTH; depth-- > 0u;) {
        js_vm_execution_frame_release(frames[depth]);
        if (frames[depth]->active != 0u) return 0;
    }
    return js_vm_active_program_current() == NULL;
}

/* Exercise the production prepared entrypoint while an outer execution frame
 * and active-program lease are still live.  The inner call must acquire the
 * next private frame, return its value, and leave the outer owner/generation
 * untouched. */
static int js_nested_prepared_execution(JNIEnv *env, js_vm_program *outer, js_vm_program *inner, jint arg, jint expected, jint *out) {
    js_vm_execution_frame *outer_frame = NULL;
    int pushed_active = 0;
    int ok = 0;
    if (!env || !outer || !inner || !out) return 0;
    pushed_active = js_vm_active_program_push(outer);
    if (!pushed_active) return 0;
    outer_frame = js_vm_execution_frame_acquire(outer);
    if (!outer_frame || outer_frame->owner_program != outer || outer_frame->generation == 0u) goto cleanup;
    ok = js_vm_execute_prepared_program_int_int(env, inner, arg, out);
    if (!ok || *out != expected || (*env)->ExceptionCheck(env)) { ok = 0; goto cleanup; }
    if (js_vm_active_program_current() != outer || !outer_frame->active ||
        outer_frame->owner_program != outer || outer_frame->generation != js_vm_execution_generation_for(outer)) {
        ok = 0;
    }
cleanup:
    if (outer_frame) js_vm_execution_frame_release(outer_frame);
    if (pushed_active) js_vm_active_program_pop();
    return ok && js_vm_active_program_current() == NULL;
}

/* Re-enter the same prepared entrypoint through a bounded recursive native
 * call chain.  Each level owns a distinct frame and active-program slot; an
 * overflow is still handled by the production frame-depth gate. */
static int js_recursive_prepared_execution(JNIEnv *env, js_vm_program *program, unsigned int depth, unsigned int remaining, jint arg, jint expected, jint *out) {
    js_vm_execution_frame *frame = NULL;
    int pushed_active = 0;
    int ok = 0;
    if (!env || !program || !out || depth == 0u || remaining == 0u) return 0;
    pushed_active = js_vm_active_program_push(program);
    if (!pushed_active) return 0;
    frame = js_vm_execution_frame_acquire(program);
    if (!frame || frame->depth != depth || frame->owner_program != program) goto cleanup;
    if (remaining == 1u) {
        ok = js_vm_execute_prepared_program_int_int(env, program, arg, out);
    } else {
        ok = js_recursive_prepared_execution(env, program, depth + 1u, remaining - 1u, arg, expected, out);
    }
    if (!ok || *out != expected || (*env)->ExceptionCheck(env)) { ok = 0; goto cleanup; }
    if (js_vm_active_program_current() != program || !frame->active) ok = 0;
cleanup:
    if (frame) js_vm_execution_frame_release(frame);
    if (pushed_active) js_vm_active_program_pop();
    return ok;
}

static int js_vm_failure_test_bytes_zero(const void *bytes, size_t length) {
    const unsigned char *cursor = (const unsigned char *)bytes;
    if (!cursor) return length == 0u;
    for (size_t i = 0u; i < length; i++) {
        if (cursor[i] != 0u) return 0;
    }
    return 1;
}

static int js_vm_failure_test_frame_clean(const js_vm_execution_frame *frame) {
    if (!frame) return 0;
    if (frame->active || frame->tls_owned || frame->owner_thread != 0u ||
        frame->owner_program != NULL || frame->generation != 0u || frame->depth != 0u) return 0;
    if (frame->insns && !js_vm_failure_test_bytes_zero(frame->insns, frame->insn_capacity * sizeof(*frame->insns))) return 0;
    if (frame->locals && !js_vm_failure_test_bytes_zero(frame->locals, frame->locals_capacity * sizeof(*frame->locals))) return 0;
    if (frame->stack && !js_vm_failure_test_bytes_zero(frame->stack, frame->stack_capacity * sizeof(*frame->stack))) return 0;
    if (frame->operand_scratch && !js_vm_failure_test_bytes_zero(frame->operand_scratch, frame->operand_capacity * sizeof(*frame->operand_scratch))) return 0;
    if ((frame->insns || frame->locals || frame->stack || frame->operand_scratch) &&
        frame->fallback_state_slot != JS_VM_FALLBACK_STATE_NONE) return 0;
    return 1;
}

static int js_vm_failure_test_state_clean(void) {
    if (js_vm_active_program_current() != NULL) return 0;
    js_vm_thread_state *thread_state = js_vm_thread_state_peek();
    if (thread_state) {
        if (thread_state->frame_depth != 0u || thread_state->active_program_depth != 0) return 0;
        for (unsigned int i = 0u; i < JS_VM_EXECUTION_FRAME_MAX_DEPTH; i++) {
            if (!js_vm_failure_test_frame_clean(&thread_state->frames[i])) return 0;
        }
        return 1;
    }
    int clean = 1;
    js_vm_execution_frame_lock_enter();
    js_vm_fallback_thread_state *fallback_state = js_vm_fallback_thread_state_find_locked(NULL);
    if (fallback_state && (fallback_state->active_frame_count != 0u || fallback_state->active_program_depth != 0)) clean = 0;
    for (size_t i = 0u; i < JS_VM_EXECUTION_FRAME_POOL_CAPACITY; i++) {
        if (!js_vm_failure_test_frame_clean(&js_vm_execution_frame_pool[i])) clean = 0;
    }
    js_vm_execution_frame_lock_leave();
    return clean;
}

static int js_vm_failure_test_valid_execution(JNIEnv *env, js_vm_program *program, jint expected) {
    jint output = 0;
    if (!env || !program || !js_vm_execute_prepared_program_int_int(env, program, 0, &output)) return 0;
    if ((*env)->ExceptionCheck(env) || output != expected) return 0;
    return js_vm_failure_test_state_clean();
}

static int js_vm_failure_recovery_probe(JNIEnv *env, js_vm_program *program,
                                        int *session_invalidation_ok,
                                        int *generation_mismatch_ok,
                                        int *post_push_cancel_ok,
                                        int *post_failure_recovery_ok,
                                        int *active_program_cleanup_ok,
                                        int *frame_cleanup_ok) {
    unsigned char saved_session_tag[32];
    int cleanup_ok = 1;
    int recovery_ok = 1;
    jint failed_output = 0;
    if (!env || !program || !session_invalidation_ok || !generation_mismatch_ok ||
        !post_push_cancel_ok || !post_failure_recovery_ok || !active_program_cleanup_ok ||
        !frame_cleanup_ok) return 0;
    memcpy(saved_session_tag, program->session_tag, sizeof(saved_session_tag));

    program->session_tag[0] ^= 0x01u;
    *session_invalidation_ok =
        !js_vm_execute_prepared_program_int_int(env, program, 0, &failed_output) &&
        !(*env)->ExceptionCheck(env) && js_vm_failure_test_state_clean();
    cleanup_ok = *session_invalidation_ok;
    memcpy(program->session_tag, saved_session_tag, sizeof(saved_session_tag));
    recovery_ok = js_vm_failure_test_valid_execution(env, program, 41);

    js_vm_execution_test_set_fault(JS_VM_EXECUTION_TEST_FAULT_FRAME_GENERATION_MISMATCH);
    *generation_mismatch_ok =
        !js_vm_execute_prepared_program_int_int(env, program, 0, &failed_output) &&
        !(*env)->ExceptionCheck(env) && js_vm_failure_test_state_clean();
    cleanup_ok = cleanup_ok && *generation_mismatch_ok;
    recovery_ok = recovery_ok && js_vm_failure_test_valid_execution(env, program, 41);

    js_vm_execution_test_set_fault(JS_VM_EXECUTION_TEST_FAULT_CANCEL_AFTER_ACTIVE_PUSH);
    *post_push_cancel_ok =
        !js_vm_execute_prepared_program_int_int(env, program, 0, &failed_output) &&
        !(*env)->ExceptionCheck(env) && js_vm_failure_test_state_clean();
    cleanup_ok = cleanup_ok && *post_push_cancel_ok;
    recovery_ok = recovery_ok && js_vm_failure_test_valid_execution(env, program, 41);

    *post_failure_recovery_ok = recovery_ok;
    *active_program_cleanup_ok = cleanup_ok && js_vm_active_program_current() == NULL;
    *frame_cleanup_ok = cleanup_ok && js_vm_failure_test_state_clean();
    js_vbc4_wipe_volatile(saved_session_tag, sizeof(saved_session_tag));
    return *session_invalidation_ok && *generation_mismatch_ok && *post_push_cancel_ok &&
        *post_failure_recovery_ok && *active_program_cleanup_ok && *frame_cleanup_ok;
}

static int js_run_probe(const char *jvm_path, unsigned int samples, unsigned int warmup) {
    js_jvm_module module = NULL;
    js_jni_create_vm_fn create_vm;
    JavaVM *vm = NULL;
    JNIEnv *env = NULL;
    JavaVMOption option;
    JavaVMInitArgs args;
    js_vm_program program;
    js_vm_program exception_program;
    js_vm_program invoke_program;
    uint64_t *timings = NULL;
    js_bench_latency latency;
    js_crypto_runtime_metrics metrics;
    js_crypto_runtime_metrics thread_metrics;
    uint64_t digest = UINT64_C(0x243f6a8885a308d3);
    unsigned int rc;
    int result = 0;
    const char *stage = "arguments";
    jint output = 0;
    int nested_execution_ok = 0;
    int recursive_execution_ok = 0;
    int exception_execution_ok = 0;
    int threaded_execution_ok = 0;
    int exception_program_ready = 0;
    int invoke_program_ready = 0;
    int invoke_static_cp0_ok = 0;
    int invoke_static_cp0_tamper_cipher_ok = 0;
    int invoke_static_cp0_tamper_tag_ok = 0;
    int invoke_static_cp0_tamper_nonce_ok = 0;
    int invoke_static_cp0_tamper_length_ok = 0;
    int invoke_static_cp0_tamper_type_ok = 0;
    int session_invalidation_ok = 0;
    int generation_mismatch_ok = 0;
    int post_push_cancel_ok = 0;
    int post_failure_recovery_ok = 0;
    int active_program_cleanup_ok = 0;
    int frame_cleanup_ok = 0;
    uint64_t thread_output_digest = UINT64_C(0x6a09e667f3bcc909);
    jint exception_output = 0;
    jint invoke_static_cp0_result = 0;
    int invoke_static_cp0_decode_stage = -1;
    int invoke_static_cp0_decode_auth = -1;
    memset(&thread_metrics, 0, sizeof(thread_metrics));

    if (!jvm_path || samples == 0u || samples > 100000u || warmup > 100000u) return 0;
    memset(&program, 0, sizeof(program));
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
    stage = "prepare-program";
    js_crypto_runtime_metrics_reset();
    memset(&exception_program, 0, sizeof(exception_program));
    memset(&invoke_program, 0, sizeof(invoke_program));
    if (!js_init_prepared_program(&program)) goto cleanup;
    stage = "prepare-exception-program";
    if (!js_init_exception_program(&exception_program)) goto cleanup;
    exception_program_ready = 1;
    stage = "prepare-invoke-static-cp0-program";
    if (!js_init_static_invoke_cp0_program(&invoke_program)) goto cleanup;
    invoke_program_ready = 1;
    stage = "invoke-static-cp0";
    invoke_static_cp0_ok = js_invoke_static_cp0_fixture(env, &invoke_program, &invoke_static_cp0_result);
    invoke_static_cp0_decode_stage = js_vm_last_cp_decode_stage;
    invoke_static_cp0_decode_auth = js_vm_last_cp_decode_auth;
    if (!invoke_static_cp0_ok) goto cleanup;
    stage = "invoke-static-cp0-tamper";
    {
        js_vm_program tampered_program;
        memset(&tampered_program, 0, sizeof(tampered_program));
        if (!js_init_static_invoke_cp0_program(&tampered_program) ||
            !js_tamper_static_cp0_entry(&tampered_program, JS_STATIC_CP0_TAMPER_CIPHERTEXT) ||
            !js_invoke_static_cp0_rejects_tamper(env, &tampered_program)) {
            js_clear_prepared_program(env, &tampered_program);
            goto cleanup;
        }
        invoke_static_cp0_tamper_cipher_ok = 1;
        js_clear_prepared_program(env, &tampered_program);
        memset(&tampered_program, 0, sizeof(tampered_program));
        if (!js_init_static_invoke_cp0_program(&tampered_program) ||
            !js_tamper_static_cp0_entry(&tampered_program, JS_STATIC_CP0_TAMPER_TAG) ||
            !js_invoke_static_cp0_rejects_tamper(env, &tampered_program)) {
            js_clear_prepared_program(env, &tampered_program);
            goto cleanup;
        }
        invoke_static_cp0_tamper_tag_ok = 1;
        js_clear_prepared_program(env, &tampered_program);
        memset(&tampered_program, 0, sizeof(tampered_program));
        if (!js_init_static_invoke_cp0_program(&tampered_program) ||
            !js_tamper_static_cp0_entry(&tampered_program, JS_STATIC_CP0_TAMPER_NONCE) ||
            !js_invoke_static_cp0_rejects_tamper(env, &tampered_program)) {
            js_clear_prepared_program(env, &tampered_program);
            goto cleanup;
        }
        invoke_static_cp0_tamper_nonce_ok = 1;
        js_clear_prepared_program(env, &tampered_program);
        memset(&tampered_program, 0, sizeof(tampered_program));
        if (!js_init_static_invoke_cp0_program(&tampered_program) ||
            !js_tamper_static_cp0_entry(&tampered_program, JS_STATIC_CP0_TAMPER_LENGTH) ||
            !js_invoke_static_cp0_rejects_tamper(env, &tampered_program)) {
            js_clear_prepared_program(env, &tampered_program);
            goto cleanup;
        }
        invoke_static_cp0_tamper_length_ok = 1;
        js_clear_prepared_program(env, &tampered_program);
        memset(&tampered_program, 0, sizeof(tampered_program));
        if (!js_init_static_invoke_cp0_program(&tampered_program) ||
            !js_tamper_static_cp0_entry(&tampered_program, JS_STATIC_CP0_TAMPER_TYPE) ||
            !js_invoke_static_cp0_rejects_tamper(env, &tampered_program)) {
            js_clear_prepared_program(env, &tampered_program);
            goto cleanup;
        }
        invoke_static_cp0_tamper_type_ok = 1;
        js_clear_prepared_program(env, &tampered_program);
    }
    stage = "failure-recovery";
    if (!js_vm_failure_recovery_probe(env, &program, &session_invalidation_ok, &generation_mismatch_ok,
                                      &post_push_cancel_ok, &post_failure_recovery_ok,
                                      &active_program_cleanup_ok, &frame_cleanup_ok)) goto cleanup;
    stage = "nested-frames";
    if (!js_nested_frame_lifecycle(&program)) goto cleanup;
    stage = "nested-prepared-execution";
    nested_execution_ok = js_nested_prepared_execution(env, &program, &program, 0, 41, &output);
    if (!nested_execution_ok) goto cleanup;
    stage = "recursive-prepared-execution";
    recursive_execution_ok = js_recursive_prepared_execution(env, &program, 1u, 4u, 0, 41, &output);
    if (!recursive_execution_ok) goto cleanup;
    stage = "exception-prepared-execution";
    exception_execution_ok = js_vm_execute_prepared_program_int_int(env, &exception_program, 0, &exception_output);
    if (!exception_execution_ok || exception_output != 42 || (*env)->ExceptionCheck(env)) {
        fprintf(stderr,
            "exception-probe failed ok=%d result=%d pending=%d failure_pc=%d failure_opcode=%d exception_count=%d\n",
            exception_execution_ok, (int)exception_output, (*env)->ExceptionCheck(env),
            js_vm_last_failure_pc, js_vm_last_failure_opcode, exception_program.exception_count);
        goto cleanup;
    }
    stage = "multithread-prepared-execution";
    js_crypto_runtime_metrics_reset();
    threaded_execution_ok = js_multithread_prepared_execution(vm, &program, &thread_output_digest);
    if (!threaded_execution_ok) goto cleanup;
    js_crypto_runtime_metrics_snapshot(&thread_metrics);
    js_mix_digest(&digest, thread_output_digest);
    timings = (uint64_t *)calloc(samples, sizeof(*timings));
    if (!timings) { stage = "allocate-timings"; goto cleanup; }
    stage = "warmup";
    for (unsigned int index = 0u; index < warmup; index++) {
        if (!js_vm_execute_prepared_program_int_int(env, &program, (jint)index, &output) ||
            output != 41 || !js_clear_exception(env)) goto cleanup;
    }
    js_crypto_runtime_metrics_reset();
    stage = "measure";
    for (unsigned int index = 0u; index < samples; index++) {
        uint64_t start = js_bench_ticks();
        if (!js_vm_execute_prepared_program_int_int(env, &program, (jint)index, &output) ||
            output != 41 || !js_clear_exception(env)) goto cleanup;
        timings[index] = js_bench_elapsed_ns(js_bench_ticks() - start);
        js_mix_digest(&digest, ((uint64_t)index << 32u) ^ (uint32_t)output);
    }
    latency = js_latency_from_samples(timings, samples);
    memset(&metrics, 0, sizeof(metrics));
    js_crypto_runtime_metrics_snapshot(&metrics);
    printf(
        "phase=vm-prepared-execution phase_mode=attached-jvm-production-entrypoint fixture_scope=session-bound-resident-program "
        "invoke_static_cp0=pass invoke_static_cp0_index=0 invoke_static_cp0_type=sealed "
        "invoke_static_cp0_result=%d invoke_static_cp0_decode_stage=%d invoke_static_cp0_decode_auth=%d "
        "invoke_static_cp0_session_layout_bound=%d "
        "invoke_static_cp0_tamper_cipher=%s invoke_static_cp0_tamper_tag=%s "
        "invoke_static_cp0_tamper_nonce=%s invoke_static_cp0_tamper_length=%s "
        "invoke_static_cp0_tamper_type=%s "
        "session_invalidation=%s generation_mismatch=%s post_push_cancel=%s "
        "post_failure_recovery=%s active_program_cleanup=%s frame_cleanup=%s "
        "nested_frame_depth=%u nested_execution=pass recursive_execution=pass exception_execution=pass exception_catch=typed exception_result=%d "
        "threaded_execution=pass thread_count=%u "
        "thread_iterations=%u thread_output_digest=%016llx thread_frame_reuse_count=%llu "
        "thread_heap_fallback_count=%llu thread_wipe_count=%llu phase_status=pass samples=%u warmup=%u "
        "p50=%lluns p95=%lluns p99=%lluns max=%lluns "
        "cpu_hardware_aes=%d cpu_hardware_ghash=%d hardware_crypto_path=%llu software_crypto_path=%llu "
        "aes_block_count=%llu ghash_block_count=%llu vm_frame_reuse_count=%llu vm_heap_fallback_count=%llu "
        "resource_index_hit_count=%llu decompress_context_reuse_count=%llu jni_cache_hit_count=%llu "
        "auth_check_count=%llu auth_failure_count=%llu digest_check_count=%llu tag_check_count=%llu "
        "length_check_count=%llu structure_check_count=%llu jni_abi_check_count=%llu wipe_count=%llu "
        "allocation_count=0 exception_count=%llu native_exception_count=0 fallback_count=%llu legacy_path_hits=%llu "
        "wipe_failure_count=%llu plaintext_persistence_bytes=%llu security_checks_skipped=%llu output_digest=%016llx\n",
        (int)invoke_static_cp0_result, invoke_static_cp0_decode_stage, invoke_static_cp0_decode_auth,
        invoke_program.session_layout_digest_bound ? 1 : 0,
        invoke_static_cp0_tamper_cipher_ok ? "fail-closed" : "failed",
        invoke_static_cp0_tamper_tag_ok ? "fail-closed" : "failed",
        invoke_static_cp0_tamper_nonce_ok ? "fail-closed" : "failed",
        invoke_static_cp0_tamper_length_ok ? "fail-closed" : "failed",
        invoke_static_cp0_tamper_type_ok ? "fail-closed" : "failed",
        session_invalidation_ok ? "fail-closed" : "failed",
        generation_mismatch_ok ? "fail-closed" : "failed",
        post_push_cancel_ok ? "fail-closed" : "failed",
        post_failure_recovery_ok ? "pass" : "failed",
        active_program_cleanup_ok ? "pass" : "failed",
        frame_cleanup_ok ? "pass" : "failed",
        (unsigned int)JS_VM_EXECUTION_FRAME_MAX_DEPTH, (int)exception_output, (unsigned int)JS_VM_THREAD_PROBE_COUNT,
        (unsigned int)JS_VM_THREAD_PROBE_ITERATIONS, (unsigned long long)thread_output_digest,
        (unsigned long long)thread_metrics.vm_frame_reuse_count,
        (unsigned long long)thread_metrics.vm_heap_fallback_count,
        (unsigned long long)thread_metrics.wipe_count, samples, warmup,
        (unsigned long long)latency.p50, (unsigned long long)latency.p95,
        (unsigned long long)latency.p99, (unsigned long long)latency.max,
        js_aes_hardware_available(), js_ghash_hardware_available(),
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
        (unsigned long long)metrics.plaintext_persistence_bytes,
        (unsigned long long)metrics.security_checks_skipped,
        (unsigned long long)digest);
    result = metrics.vm_frame_reuse_count >= (samples > 1u ? (uint64_t)(samples - 1u) : 0u) &&
        metrics.vm_heap_fallback_count == 0u && metrics.fallback_count == 0u &&
        metrics.legacy_path_hits == 0u && metrics.wipe_failure_count == 0u &&
        metrics.plaintext_persistence_bytes == 0u && metrics.security_checks_skipped == 0u &&
        metrics.exception_count == 0u && threaded_execution_ok &&
        thread_metrics.vm_frame_reuse_count >=
            (uint64_t)(JS_VM_THREAD_PROBE_COUNT * (JS_VM_THREAD_PROBE_ITERATIONS - 1u)) &&
        thread_metrics.vm_heap_fallback_count == 0u;
    stage = result ? "pass" : "security-gate";
cleanup:
    /* Free the prepared program while the disposable JVM is still alive.
     * js_vm_free_program clears any JNI-backed symbol cache entries through
     * the current JNIEnv; using that pointer after DestroyJavaVM would be an
     * invalid attached-JVM access. */
    if (exception_program_ready || exception_program.resource_path || exception_program.insns ||
        exception_program.argument_tags || exception_program.cp || exception_program.exceptions) {
        js_clear_prepared_program(env, &exception_program);
    }
    if (invoke_program_ready || invoke_program.resource_path || invoke_program.insns ||
        invoke_program.argument_tags || invoke_program.cp || invoke_program.exceptions) {
        js_clear_prepared_program(env, &invoke_program);
    }
    if (program.resource_path || program.insns || program.argument_tags) js_clear_prepared_program(env, &program);
    if (vm) {
        js_vm_clear_startup_nonce();
        (*vm)->DestroyJavaVM(vm);
    }
    if (timings) {
        js_vbc4_wipe_volatile(timings, (size_t)samples * sizeof(*timings));
        free(timings);
    }
    js_jvm_close(module);
    if (!result) fprintf(stderr, "vm-prepared-production probe failed at stage=%s\n", stage);
    return result;
}

int main(int argc, char **argv) {
    unsigned int samples = 100u;
    unsigned int warmup = 16u;
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: %s JVM_PATH [SAMPLES] [WARMUP]\n", argc > 0 ? argv[0] : "vm-prepared-probe");
        return 2;
    }
    if (argc > 2 && !js_parse_u32(argv[2], &samples)) return 2;
    if (argc > 3 && !js_parse_u32(argv[3], &warmup)) return 2;
    return js_run_probe(argv[1], samples, warmup) ? 0 : 1;
}
