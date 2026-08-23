/*
 * Native execution-frame lifecycle probe.
 *
 * This fixture intentionally includes js_vm_core.c so it can exercise the
 * file-local execution-frame arena without widening the production JNI ABI.
 * Build it with the remaining native sources, JS_VM_EXECUTION_FRAME_TEST=1,
 * JS_VM_FORCE_FRAME_POOL=0/1, and the test-only TLS/FLS init-failure lane.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#endif

#ifndef JS_VM_EXECUTION_FRAME_TEST
#error "vm_execution_frame_probe.c requires JS_VM_EXECUTION_FRAME_TEST=1"
#endif

#include "js_vm_core.c"

typedef struct js_vm_frame_thread_result {
    js_vm_program *program;
    uintptr_t frame_address;
    uintptr_t owner_token;
    int status;
} js_vm_frame_thread_result;

typedef struct js_vm_layout_thread_result {
    unsigned char expected[32];
    volatile int *ready_count;
    volatile int *release_workers;
    int status;
} js_vm_layout_thread_result;

static int js_vm_layout_atomic_load(volatile int *value) {
#ifdef _WIN32
    return (int)InterlockedCompareExchange((volatile LONG *)value, 0, 0);
#else
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#endif
}

static void js_vm_layout_atomic_increment(volatile int *value) {
#ifdef _WIN32
    (void)InterlockedIncrement((volatile LONG *)value);
#else
    (void)__atomic_fetch_add(value, 1, __ATOMIC_ACQ_REL);
#endif
}

static void js_vm_layout_atomic_store(volatile int *value, int next) {
#ifdef _WIN32
    (void)InterlockedExchange((volatile LONG *)value, (LONG)next);
#else
    __atomic_store_n(value, next, __ATOMIC_RELEASE);
#endif
}

static void js_vm_layout_yield(void) {
#ifdef _WIN32
    SwitchToThread();
#else
    sched_yield();
#endif
}

static int js_vm_frame_test_all_zero(const void *bytes, size_t length) {
    const unsigned char *cursor = (const unsigned char *)bytes;
    if (!cursor) return 0;
    for (size_t i = 0u; i < length; i++) {
        if (cursor[i] != 0u) return 0;
    }
    return 1;
}

static int js_vm_frame_test_all_equal(const void *bytes, size_t length, unsigned char value) {
    const unsigned char *cursor = (const unsigned char *)bytes;
    if (!cursor) return 0;
    for (size_t i = 0u; i < length; i++) {
        if (cursor[i] != value) return 0;
    }
    return 1;
}

static int js_vm_frame_test_expect(int condition, const char *message) {
    if (condition) return 1;
    fprintf(stderr, "VM execution frame probe: %s\n", message);
    return 0;
}

static int js_vm_frame_test_scoped_layout_digest_slot_zero(unsigned int slot) {
    int result = 0;
    if (slot >= JS_VM_SCOPED_LAYOUT_DIGEST_MAX_DEPTH) return 0;
    js_vm_thread_state *thread_state = js_vm_thread_state_peek();
    if (thread_state) {
        return js_vm_frame_test_all_zero(thread_state->scoped_layout_digests[slot], 32u);
    }
    js_vm_execution_frame_lock_enter();
    js_vm_fallback_thread_state *fallback_state = js_vm_fallback_thread_state_find_locked(NULL);
    if (fallback_state) {
        result = js_vm_frame_test_all_zero(fallback_state->scoped_layout_digests[slot], 32u);
    }
    js_vm_execution_frame_lock_leave();
    return result;
}

static void js_vm_frame_test_init_program(js_vm_program *program) {
    memset(program, 0, sizeof(*program));
    program->entry_token = (jlong)INT64_C(0x1122334455667788);
    program->build_seed = 0x13572468;
    program->dispatch_profile_tag = 0x2468ACE1u;
    program->session_bound = 1;
    for (size_t i = 0u; i < sizeof(program->session_leaf); i++) {
        program->session_leaf[i] = (unsigned char)(i * 13u + 7u);
        program->session_tag[i] = (unsigned char)(i * 17u + 11u);
        program->method_identity[i] = (unsigned char)(i * 19u + 3u);
        program->owner_identity[i] = (unsigned char)(i * 23u + 5u);
    }
}

static int js_vm_frame_test_reuse_and_cleanup(js_vm_program *program) {
    js_vm_execution_frame *frame;
    js_vm_execution_frame *reused;
    js_crypto_runtime_metrics metrics;
    void *insns;
    void *locals;
    void *stack;
    void *operands;
    unsigned int saved_generation;
    int saved_build_seed;
    char *owned_uninit_type;

    js_crypto_runtime_metrics_reset();
    frame = js_vm_execution_frame_acquire(program);
    if (!js_vm_frame_test_expect(frame != NULL, "initial frame acquisition failed")) return 0;
#if JS_VM_FORCE_FRAME_POOL || JS_VM_FORCE_TLS_FLS_INIT_FAILURE
    if (!js_vm_frame_test_expect(frame->tls_owned == 0u, "forced fallback acquired a TLS/FLS frame")) return 0;
#else
    if (!js_vm_frame_test_expect(frame->tls_owned == 1u, "normal path did not acquire a TLS/FLS frame")) return 0;
#endif
    if (!js_vm_frame_test_expect(frame->active == 1u && frame->owner_program == program,
            "acquired frame lost owner binding")) return 0;
    if (!js_vm_frame_test_expect(frame->generation == js_vm_execution_generation_for(program),
            "acquired frame generation is not artifact/session bound")) return 0;
    if (!js_vm_frame_test_expect(
            js_vm_execution_frame_reserve_insns(frame, 7u) &&
            js_vm_execution_frame_reserve_values(&frame->locals, &frame->locals_capacity, 5u) &&
            js_vm_execution_frame_reserve_values(&frame->stack, &frame->stack_capacity, 9u) &&
            js_vm_execution_frame_reserve_operands(frame, 11u),
            "frame scratch allocation failed")) return 0;

    owned_uninit_type = (char *)malloc(12u);
    if (!js_vm_frame_test_expect(owned_uninit_type != NULL, "UNINIT cleanup allocation failed")) return 0;
    memcpy(owned_uninit_type, "frame-probe", 12u);
    frame->locals[0] = js_vm_uninit_value(41, owned_uninit_type);
    frame->stack[0] = js_vm_int_value(0x1357);
    memset(frame->insns, 0xA1, frame->insn_capacity * sizeof(*frame->insns));
    memset(frame->operand_scratch, 0xB2, frame->operand_capacity * sizeof(*frame->operand_scratch));
    insns = frame->insns;
    locals = frame->locals;
    stack = frame->stack;
    operands = frame->operand_scratch;
    saved_generation = frame->generation;
    saved_build_seed = program->build_seed;
    program->build_seed ^= 0x55AA33CC;
    if (!js_vm_frame_test_expect(saved_generation != js_vm_execution_generation_for(program),
            "stale generation was not distinguished from the current program generation")) return 0;
    program->build_seed = saved_build_seed;

    js_vm_execution_frame_release(frame);
    if (!js_vm_frame_test_expect(frame->active == 0u && frame->generation == 0u &&
            frame->owner_thread == 0u && frame->owner_program == NULL && frame->depth == 0u,
            "released frame retained active ownership state")) return 0;
    if (!js_vm_frame_test_expect(
            js_vm_frame_test_all_zero(insns, frame->insn_capacity * sizeof(*frame->insns)) &&
            js_vm_frame_test_all_zero(locals, frame->locals_capacity * sizeof(*frame->locals)) &&
            js_vm_frame_test_all_zero(stack, frame->stack_capacity * sizeof(*frame->stack)) &&
            js_vm_frame_test_all_zero(operands, frame->operand_capacity * sizeof(*frame->operand_scratch)),
            "released frame retained mutable instruction, locals, stack, or operand bytes")) return 0;

    reused = js_vm_execution_frame_acquire(program);
    if (!js_vm_frame_test_expect(reused == frame, "frame arena did not return the released frame")) return 0;
    if (!js_vm_frame_test_expect(reused->insns == insns && reused->locals == locals &&
            reused->stack == stack && reused->operand_scratch == operands,
            "reused frame reallocated mutable scratch storage")) return 0;
    js_crypto_runtime_metrics_snapshot(&metrics);
    if (!js_vm_frame_test_expect(metrics.vm_frame_reuse_count != 0u,
            "frame reuse did not update runtime metrics")) return 0;
    js_vm_execution_frame_release(reused);
    return 1;
}

static int js_vm_frame_test_allocation_failure_preserves_state(js_vm_program *program) {
    js_vm_execution_frame *frame = js_vm_execution_frame_acquire(program);
    js_vm_insn *insns;
    js_vm_value *locals;
    js_vm_value *stack;
    jint *operands;
    size_t insn_capacity;
    size_t locals_capacity;
    size_t stack_capacity;
    size_t operand_capacity;

    if (!js_vm_frame_test_expect(frame != NULL, "allocation-failure frame acquisition failed")) return 0;
    if (!js_vm_frame_test_expect(
            js_vm_execution_frame_reserve_insns(frame, 2u) &&
            js_vm_execution_frame_reserve_values(&frame->locals, &frame->locals_capacity, 2u) &&
            js_vm_execution_frame_reserve_values(&frame->stack, &frame->stack_capacity, 2u) &&
            js_vm_execution_frame_reserve_operands(frame, 2u),
            "allocation-failure fixture setup failed")) {
        js_vm_execution_frame_release(frame);
        return 0;
    }
    frame->insns[0].opcode = 0x51;
    frame->locals[0] = js_vm_int_value(0x2468);
    frame->stack[0] = js_vm_long_value((jlong)INT64_C(0x1122334455667788));
    frame->operand_scratch[0] = 0x13572468;
    insns = frame->insns;
    locals = frame->locals;
    stack = frame->stack;
    operands = frame->operand_scratch;
    insn_capacity = frame->insn_capacity;
    locals_capacity = frame->locals_capacity;
    stack_capacity = frame->stack_capacity;
    operand_capacity = frame->operand_capacity;

#define JS_VM_FRAME_EXPECT_FORCED_FAILURE(call, message) \
    do { \
        js_vm_execution_frame_test_fail_allocation_after(0u); \
        if (!js_vm_frame_test_expect(!(call), message)) { \
            js_vm_execution_frame_test_restore_allocations(); \
            js_vm_execution_frame_release(frame); \
            return 0; \
        } \
        js_vm_execution_frame_test_restore_allocations(); \
    } while (0)

    JS_VM_FRAME_EXPECT_FORCED_FAILURE(
        js_vm_execution_frame_reserve_insns(frame, insn_capacity + 1u),
        "instruction growth did not fail under allocation injection");
    JS_VM_FRAME_EXPECT_FORCED_FAILURE(
        js_vm_execution_frame_reserve_values(&frame->locals, &frame->locals_capacity, locals_capacity + 1u),
        "locals growth did not fail under allocation injection");
    JS_VM_FRAME_EXPECT_FORCED_FAILURE(
        js_vm_execution_frame_reserve_values(&frame->stack, &frame->stack_capacity, stack_capacity + 1u),
        "stack growth did not fail under allocation injection");
    JS_VM_FRAME_EXPECT_FORCED_FAILURE(
        js_vm_execution_frame_reserve_operands(frame, operand_capacity + 1u),
        "operand growth did not fail under allocation injection");

#undef JS_VM_FRAME_EXPECT_FORCED_FAILURE

    if (!js_vm_frame_test_expect(
            frame->insns == insns && frame->locals == locals && frame->stack == stack &&
            frame->operand_scratch == operands && frame->insn_capacity == insn_capacity &&
            frame->locals_capacity == locals_capacity && frame->stack_capacity == stack_capacity &&
            frame->operand_capacity == operand_capacity && frame->insns[0].opcode == 0x51 &&
            frame->locals[0].type == JS_VM_VAL_INT && frame->locals[0].i == 0x2468 &&
            frame->stack[0].type == JS_VM_VAL_LONG &&
            frame->stack[0].l == (jlong)INT64_C(0x1122334455667788) &&
            frame->operand_scratch[0] == 0x13572468,
            "failed frame growth replaced or corrupted reusable state")) {
        js_vm_execution_frame_release(frame);
        return 0;
    }
    js_vm_execution_frame_release(frame);
    return js_vm_frame_test_expect(
        frame->active == 0u && frame->generation == 0u && frame->owner_program == NULL &&
        js_vm_frame_test_all_zero(insns, insn_capacity * sizeof(*insns)) &&
        js_vm_frame_test_all_zero(locals, locals_capacity * sizeof(*locals)) &&
        js_vm_frame_test_all_zero(stack, stack_capacity * sizeof(*stack)) &&
        js_vm_frame_test_all_zero(operands, operand_capacity * sizeof(*operands)),
        "allocation-failure cleanup retained frame state");
}

static int js_vm_frame_test_nested_lifo(js_vm_program *program) {
    js_vm_execution_frame *frames[JS_VM_EXECUTION_FRAME_MAX_DEPTH];
    js_vm_execution_frame *too_deep;
    size_t outer_operand_bytes;

    memset(frames, 0, sizeof(frames));
    for (unsigned int i = 0u; i < JS_VM_EXECUTION_FRAME_MAX_DEPTH; i++) {
        frames[i] = js_vm_execution_frame_acquire(program);
        if (!js_vm_frame_test_expect(frames[i] != NULL, "nested frame acquisition failed before depth limit")) return 0;
        if (!js_vm_frame_test_expect(frames[i]->depth == i + 1u, "nested frame depth was not monotonic")) return 0;
        if (!js_vm_frame_test_expect(js_vm_active_program_push(program) != 0 &&
                js_vm_active_program_current() == program,
                "nested active-program stack lost the current program")) return 0;
    }
    too_deep = js_vm_execution_frame_acquire(program);
    if (!js_vm_frame_test_expect(too_deep == NULL, "frame depth overflow did not fail closed")) return 0;

    if (!js_vm_frame_test_expect(js_vm_execution_frame_reserve_operands(frames[0], 13u),
            "outer frame operand scratch allocation failed")) return 0;
    outer_operand_bytes = frames[0]->operand_capacity * sizeof(*frames[0]->operand_scratch);
    memset(frames[0]->operand_scratch, 0xD3, outer_operand_bytes);
    js_vm_execution_frame_release(frames[0]);
    if (!js_vm_frame_test_expect(frames[0]->active == 1u && frames[0]->owner_program == program &&
            js_vm_frame_test_all_equal(frames[0]->operand_scratch, outer_operand_bytes, 0xD3),
            "out-of-order release wiped or returned a live outer frame")) return 0;

    for (unsigned int i = JS_VM_EXECUTION_FRAME_MAX_DEPTH; i-- > 0u;) {
        js_vm_active_program_pop();
        js_vm_execution_frame_release(frames[i]);
        if (!js_vm_frame_test_expect(frames[i]->active == 0u, "LIFO release retained an active frame")) return 0;
    }
    if (!js_vm_frame_test_expect(js_vm_active_program_current() == NULL,
            "active-program stack retained a nested program after cleanup")) return 0;
    return 1;
}

static void js_vm_frame_test_worker_run(js_vm_frame_thread_result *result) {
    js_vm_execution_frame *frame;
    if (!result || !result->program) return;
    frame = js_vm_execution_frame_acquire(result->program);
    if (!frame || frame->tls_owned == 0u ||
        !js_vm_execution_frame_reserve_insns(frame, 3u) ||
        !js_vm_execution_frame_reserve_values(&frame->locals, &frame->locals_capacity, 3u) ||
        !js_vm_execution_frame_reserve_operands(frame, 3u)) {
        result->status = 1;
        return;
    }
    memset(frame->insns, 0x7C, frame->insn_capacity * sizeof(*frame->insns));
    memset(frame->locals, 0x6B, frame->locals_capacity * sizeof(*frame->locals));
    memset(frame->operand_scratch, 0x5A, frame->operand_capacity * sizeof(*frame->operand_scratch));
    result->frame_address = (uintptr_t)(void *)frame;
    result->owner_token = frame->owner_thread;
    result->status = 0;
    /* Deliberately leave the worker frame active: the FLS/pthread destructor
     * must wipe and release it at thread exit. */
}

static void js_vm_layout_test_worker_run(js_vm_layout_thread_result *result) {
    unsigned char observed[32];
    int installed = 0;
    if (!result || !result->ready_count || !result->release_workers) return;
    result->status = 1;
    memset(observed, 0, sizeof(observed));
    installed = js_vbc4_install_scoped_layout_digest(result->expected);
    js_vm_layout_atomic_increment(result->ready_count);
    while (js_vm_layout_atomic_load(result->release_workers) == 0) js_vm_layout_yield();
    if (installed && js_vbc4_scoped_layout_digest_copy(observed) &&
        memcmp(observed, result->expected, sizeof(observed)) == 0) {
        result->status = 0;
    }
    js_vbc4_clear_scoped_layout_digest();
    js_vbc4_wipe_volatile(observed, sizeof(observed));
}

static int js_vm_frame_test_scoped_layout_digest_nested_restore(void) {
    unsigned char outer[32];
    unsigned char inner[32];
    unsigned char observed[32];
    int ok = 1;
    for (size_t index = 0u; index < sizeof(outer); index++) {
        outer[index] = (unsigned char)(0x17u + index * 5u);
        inner[index] = (unsigned char)(0xA3u - index * 3u);
    }
    memset(observed, 0, sizeof(observed));
    /* Ensure this probe starts from an empty scope in either TLS/FLS or the
     * owner-validated fallback lane. */
    js_vbc4_clear_scoped_layout_digest();
    if (!js_vm_frame_test_expect(js_vbc4_install_scoped_layout_digest(outer),
            "outer scoped-layout digest install failed")) ok = 0;
    if (!js_vm_frame_test_expect(js_vbc4_install_scoped_layout_digest(inner),
            "nested scoped-layout digest install failed")) ok = 0;
    if (!js_vm_frame_test_expect(
            js_vbc4_scoped_layout_digest_copy(observed) && memcmp(observed, inner, sizeof(observed)) == 0,
            "nested scoped-layout digest did not select the inner binding")) ok = 0;
    js_vbc4_clear_scoped_layout_digest();
    if (!js_vm_frame_test_expect(js_vm_frame_test_scoped_layout_digest_slot_zero(1u),
            "nested scoped-layout cleanup did not wipe the popped inner slot")) ok = 0;
    memset(observed, 0, sizeof(observed));
    if (!js_vm_frame_test_expect(
            js_vbc4_scoped_layout_digest_copy(observed) && memcmp(observed, outer, sizeof(observed)) == 0,
            "nested scoped-layout cleanup did not restore the outer binding")) ok = 0;
    js_vbc4_clear_scoped_layout_digest();
    if (!js_vm_frame_test_expect(js_vm_frame_test_scoped_layout_digest_slot_zero(0u),
            "outer scoped-layout cleanup did not wipe the popped outer slot")) ok = 0;
    memset(observed, 0xCC, sizeof(observed));
    if (!js_vm_frame_test_expect(!js_vbc4_scoped_layout_digest_copy(observed) &&
            js_vm_frame_test_all_zero(observed, sizeof(observed)),
            "scoped-layout digest remained live after the outer cleanup")) ok = 0;
    js_vbc4_wipe_volatile(outer, sizeof(outer));
    js_vbc4_wipe_volatile(inner, sizeof(inner));
    js_vbc4_wipe_volatile(observed, sizeof(observed));
    return ok;
}

static int js_vm_frame_test_scoped_layout_digest_overflow(void) {
    unsigned char digest[32];
    unsigned char observed[32];
    int ok = 1;
    memset(digest, 0, sizeof(digest));
    memset(observed, 0, sizeof(observed));
    js_vbc4_clear_scoped_layout_digest();
    for (unsigned int depth = 0u; depth < JS_VM_SCOPED_LAYOUT_DIGEST_MAX_DEPTH; depth++) {
        for (size_t index = 0u; index < sizeof(digest); index++) {
            digest[index] = (unsigned char)(depth * 19u + index * 7u + 3u);
        }
        if (!js_vm_frame_test_expect(js_vbc4_install_scoped_layout_digest(digest),
                "scoped-layout digest stack rejected a bounded nested install")) ok = 0;
    }
    for (size_t index = 0u; index < sizeof(digest); index++) digest[index] = 0xE7u;
    if (!js_vm_frame_test_expect(!js_vbc4_install_scoped_layout_digest(digest),
            "scoped-layout digest overflow did not fail closed")) ok = 0;
    /* Overflow must not replace the last authenticated binding. The caller can
     * still unwind the already-acquired scopes explicitly. */
    for (size_t index = 0u; index < sizeof(digest); index++) {
        digest[index] = (unsigned char)((JS_VM_SCOPED_LAYOUT_DIGEST_MAX_DEPTH - 1u) * 19u + index * 7u + 3u);
    }
    if (!js_vm_frame_test_expect(js_vbc4_scoped_layout_digest_copy(observed) &&
            memcmp(observed, digest, sizeof(observed)) == 0,
            "scoped-layout overflow replaced the outermost live binding")) ok = 0;
    for (unsigned int depth = 0u; depth < JS_VM_SCOPED_LAYOUT_DIGEST_MAX_DEPTH; depth++) {
        js_vbc4_clear_scoped_layout_digest();
    }
    memset(observed, 0xCC, sizeof(observed));
    if (!js_vm_frame_test_expect(!js_vbc4_scoped_layout_digest_copy(observed) &&
            js_vm_frame_test_all_zero(observed, sizeof(observed)),
            "scoped-layout overflow unwind retained a digest")) ok = 0;
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    js_vbc4_wipe_volatile(observed, sizeof(observed));
    return ok;
}

#ifdef _WIN32
static DWORD WINAPI js_vm_frame_test_worker_entry(LPVOID opaque) {
    js_vm_frame_test_worker_run((js_vm_frame_thread_result *)opaque);
    return 0u;
}

static DWORD WINAPI js_vm_layout_test_worker_entry(LPVOID opaque) {
    js_vm_layout_test_worker_run((js_vm_layout_thread_result *)opaque);
    return 0u;
}
#else
static void *js_vm_frame_test_worker_entry(void *opaque) {
    js_vm_frame_test_worker_run((js_vm_frame_thread_result *)opaque);
    return NULL;
}

static void *js_vm_layout_test_worker_entry(void *opaque) {
    js_vm_layout_test_worker_run((js_vm_layout_thread_result *)opaque);
    return NULL;
}
#endif

static int js_vm_frame_test_scoped_layout_digest_isolation(void) {
    js_vm_layout_thread_result results[2];
    volatile int ready_count = 0;
    volatile int release_workers = 0;
    memset(results, 0, sizeof(results));
    for (int worker_index = 0; worker_index < 2; worker_index++) {
        results[worker_index].ready_count = &ready_count;
        results[worker_index].release_workers = &release_workers;
        results[worker_index].status = 1;
        for (size_t byte_index = 0u; byte_index < sizeof(results[worker_index].expected); byte_index++) {
            results[worker_index].expected[byte_index] =
                (unsigned char)(0x31u + (unsigned int)worker_index * 0x53u + (unsigned int)byte_index * 7u);
        }
    }
#ifdef _WIN32
    HANDLE workers[2] = {
        CreateThread(NULL, 0u, js_vm_layout_test_worker_entry, &results[0], 0u, NULL),
        CreateThread(NULL, 0u, js_vm_layout_test_worker_entry, &results[1], 0u, NULL),
    };
    if (!js_vm_frame_test_expect(workers[0] != NULL && workers[1] != NULL,
            "failed to create scoped-layout isolation workers")) {
        if (workers[0]) CloseHandle(workers[0]);
        if (workers[1]) CloseHandle(workers[1]);
        return 0;
    }
    while (js_vm_layout_atomic_load(&ready_count) != 2) js_vm_layout_yield();
    js_vm_layout_atomic_store(&release_workers, 1);
    for (int worker_index = 0; worker_index < 2; worker_index++) {
        if (!js_vm_frame_test_expect(WaitForSingleObject(workers[worker_index], INFINITE) == WAIT_OBJECT_0,
                "scoped-layout isolation worker did not terminate")) {
            CloseHandle(workers[worker_index]);
            return 0;
        }
        CloseHandle(workers[worker_index]);
    }
#else
    pthread_t workers[2];
    if (!js_vm_frame_test_expect(
            pthread_create(&workers[0], NULL, js_vm_layout_test_worker_entry, &results[0]) == 0 &&
                pthread_create(&workers[1], NULL, js_vm_layout_test_worker_entry, &results[1]) == 0,
            "failed to create scoped-layout isolation pthreads")) return 0;
    while (js_vm_layout_atomic_load(&ready_count) != 2) js_vm_layout_yield();
    js_vm_layout_atomic_store(&release_workers, 1);
    for (int worker_index = 0; worker_index < 2; worker_index++) {
        if (!js_vm_frame_test_expect(pthread_join(workers[worker_index], NULL) == 0,
                "scoped-layout isolation pthread did not join")) return 0;
    }
#endif
    for (int worker_index = 0; worker_index < 2; worker_index++) {
        if (!js_vm_frame_test_expect(results[worker_index].status == 0,
                "scoped layout digest crossed native thread ownership")) return 0;
        js_vbc4_wipe_volatile(results[worker_index].expected, sizeof(results[worker_index].expected));
    }
    return 1;
}

static int js_vm_frame_test_thread_exit_cleanup(js_vm_program *program) {
#if JS_VM_FORCE_FRAME_POOL || JS_VM_FORCE_TLS_FLS_INIT_FAILURE
    (void)program;
    return 1;
#else
    js_vm_execution_frame *main_frame = js_vm_execution_frame_acquire(program);
    js_vm_frame_thread_result result;
    unsigned int destroy_count_before;
    if (!js_vm_frame_test_expect(main_frame != NULL && main_frame->tls_owned == 1u,
            "main thread did not use a TLS/FLS frame")) return 0;
    memset(&result, 0, sizeof(result));
    result.program = program;
    destroy_count_before = js_vm_execution_frame_test_thread_state_destroy_count;
#ifdef _WIN32
    HANDLE worker = CreateThread(NULL, 0u, js_vm_frame_test_worker_entry, &result, 0u, NULL);
    if (!js_vm_frame_test_expect(worker != NULL, "failed to create TLS/FLS worker thread")) return 0;
    if (!js_vm_frame_test_expect(WaitForSingleObject(worker, INFINITE) == WAIT_OBJECT_0,
            "TLS/FLS worker thread did not terminate")) {
        CloseHandle(worker);
        return 0;
    }
    CloseHandle(worker);
#else
    pthread_t worker;
    if (!js_vm_frame_test_expect(pthread_create(&worker, NULL, js_vm_frame_test_worker_entry, &result) == 0,
            "failed to create pthread TLS worker")) return 0;
    if (!js_vm_frame_test_expect(pthread_join(worker, NULL) == 0,
            "pthread TLS worker did not join")) return 0;
#endif
    if (!js_vm_frame_test_expect(result.status == 0 && result.frame_address != 0u && result.owner_token != 0u,
            "worker TLS/FLS frame setup failed")) return 0;
    if (!js_vm_frame_test_expect(result.frame_address != (uintptr_t)(void *)main_frame &&
            result.owner_token != main_frame->owner_thread,
            "worker reused the main thread execution frame")) return 0;
    if (!js_vm_frame_test_expect(js_vm_execution_frame_test_thread_state_destroy_count > destroy_count_before,
            "TLS/FLS destructor did not run after worker exit")) return 0;
    js_vm_execution_frame_release(main_frame);
    return 1;
#endif
}

int main(void) {
    js_vm_program program;
    js_vm_frame_test_init_program(&program);
    if (!js_vm_frame_test_reuse_and_cleanup(&program) ||
        !js_vm_frame_test_allocation_failure_preserves_state(&program) ||
        !js_vm_frame_test_nested_lifo(&program) ||
        !js_vm_frame_test_scoped_layout_digest_isolation() ||
        !js_vm_frame_test_scoped_layout_digest_nested_restore() ||
        !js_vm_frame_test_scoped_layout_digest_overflow() ||
        !js_vm_frame_test_thread_exit_cleanup(&program)) {
        return EXIT_FAILURE;
    }
    printf(
        "VM execution frame probe: PASS mode=%s allocation_failure=fail-closed "
        "depth_overflow=fail-closed layout_digest_isolation=pass layout_digest_nested_restore=pass layout_digest_overflow=fail-closed cleanup=pass destructor_count=%u\n",
#if JS_VM_FORCE_FRAME_POOL
        "fallback",
#elif JS_VM_FORCE_TLS_FLS_INIT_FAILURE
        "tls-init-failure",
#else
        "tls-fls",
#endif
        (unsigned int)js_vm_execution_frame_test_thread_state_destroy_count);
    return EXIT_SUCCESS;
}
