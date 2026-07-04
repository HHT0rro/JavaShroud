#ifndef JS_VM_DISPATCHER_H
#define JS_VM_DISPATCHER_H

#include <jni.h>
#include <stdint.h>

// Forward declare context type
typedef struct js_vm_context_t js_vm_context_t;

typedef enum {
    DISPATCHER_SWITCH = 0,
    DISPATCHER_DIRECT_THREADED = 1,
    DISPATCHER_INDIRECT_THREADED = 2,
    DISPATCHER_CALL_THREADED = 3,
    DISPATCHER_IF_NEST = 4,
    DISPATCHER_INTERPOLATION = 5
} dispatcher_profile_t;

typedef jvalue (*dispatcher_fn)(
    JNIEnv* env,
    js_vm_context_t* ctx,
    const uint8_t* program,
    uint32_t program_size
);

// Get dispatcher function for profile
dispatcher_fn js_vm_get_dispatcher(dispatcher_profile_t profile);

// Read dispatcher profile from resource (placeholder for now)
dispatcher_profile_t js_vm_read_dispatcher_profile(js_vm_context_t* ctx);

// Verify dispatcher profile auth (placeholder for now)
int js_vm_verify_dispatcher_auth(js_vm_context_t* ctx, dispatcher_profile_t profile);

// Individual dispatcher implementations
jvalue dispatch_switch(JNIEnv* env, js_vm_context_t* ctx, const uint8_t* program, uint32_t program_size);
jvalue dispatch_indirect_threaded(JNIEnv* env, js_vm_context_t* ctx, const uint8_t* program, uint32_t program_size);
jvalue dispatch_if_nest(JNIEnv* env, js_vm_context_t* ctx, const uint8_t* program, uint32_t program_size);

#ifdef __GNUC__
jvalue dispatch_direct_threaded(JNIEnv* env, js_vm_context_t* ctx, const uint8_t* program, uint32_t program_size);
#endif

#endif // JS_VM_DISPATCHER_H
