#ifndef JS_VM_INTERNAL_H
#define JS_VM_INTERNAL_H

#include "js_native_common.h"

#define JS_VM_CP_STRING 1
#define JS_VM_CP_INT 2
#define JS_VM_CP_LONG 3
#define JS_VM_CP_FLOAT 4
#define JS_VM_CP_DOUBLE 5
#define JS_VM_CP_SEALED_STRING 6

#define JS_VM_VAL_NULL 0
#define JS_VM_VAL_INT 1
#define JS_VM_VAL_LONG 2
#define JS_VM_VAL_FLOAT 3
#define JS_VM_VAL_DOUBLE 4
#define JS_VM_VAL_OBJECT 5
#define JS_VM_VAL_UNINIT 6
#define JS_VM_INVOKESPECIAL 0xB1
#define JS_VM_INVOKESTATIC 0xB2
#define JS_VM_ANEWARRAY 0xC2
#define JS_VM_CHECKCAST 0xC4
#define JS_VM_INSTANCEOF 0xC5
#define JS_VM_MULTIANEWARRAY 0xC6
#define JS_VM_IALOAD 0xD0
#define JS_VM_LALOAD 0xD1
#define JS_VM_FALOAD 0xD2
#define JS_VM_DALOAD 0xD3
#define JS_VM_AALOAD 0xD4
#define JS_VM_BALOAD 0xD5
#define JS_VM_CALOAD 0xD6
#define JS_VM_SALOAD 0xD7
#define JS_VM_IASTORE 0xD8
#define JS_VM_LASTORE 0xD9
#define JS_VM_FASTORE 0xDA
#define JS_VM_DASTORE 0xDB
#define JS_VM_AASTORE 0xDC
#define JS_VM_BASTORE 0xDD
#define JS_VM_CASTORE 0xDE
#define JS_VM_SASTORE 0xDF

typedef struct { int type; char *s; jint i; jlong l; jfloat f; jdouble d; unsigned char *enc; int enc_len; int stored_len; int plain_len; int entry_id; unsigned char stored_zstd; unsigned char key[16]; unsigned char iv[16]; } js_vm_cp;
typedef struct { jint opcode; jint op_count; jint *ops; jint opcode_epoch; } js_vm_insn;
typedef struct { jint opcode; jint flags; jint dst; jint srcA; jint srcB; jint operand; jint canonical_opcode; jint original_opcode; } js_vm_reg_insn;
typedef struct { js_vm_reg_insn *insns; int insn_count; int register_count; int super_count; uint32_t fold_digest; } js_vm_reg_program;
typedef struct { jint start; jint end; jint handler; jint type_cp; } js_vm_exception;
typedef struct {
    int cp_idx;
    int kind;
    jclass cls;
    jmethodID mid;
    jfieldID fid;
    unsigned char tag;
    char *arg_tags;
    int argc;
    unsigned char ret_tag;
    unsigned char is_constructor;
    unsigned char is_array_clone;
    unsigned char is_class_mirror;
    unsigned char is_class_resource_stream;
    unsigned char is_class_loader_define_class;
    unsigned char is_class_loader_load_class;
    unsigned char is_self_call;
    uint32_t generation;
    uintptr_t loader_identity;
    unsigned char owner_identity[32];
    unsigned char abi_version;
    unsigned char method_identity[32];
    char *type_name;
} js_vm_symbol_cache_entry;
typedef struct js_vm_program { js_vm_cp *cp; int cp_count; js_vm_insn *insns; int insn_count; int borrowed_insns; int borrowed_insn_operands; int cached_execution_ready; js_vm_reg_program reg_program; js_vm_exception *exceptions; int exception_count; int borrowed_exceptions; int cfg_exceptions_decoded; int max_stack; int max_locals; int mac_key; int build_seed; int key_mask; uint32_t resident_rotation_epoch; unsigned char nonce[16]; unsigned char session_layout_digest[32]; int session_layout_digest_bound; unsigned char session_leaf[32]; unsigned char session_tag[32]; int session_bound; int metadata_cp_index; uint32_t method_local_profile; uint32_t native_vm_profile_id; uint32_t dispatch_profile_tag; uint32_t vbc4_flags; uint32_t nested_vm_profile; jlong entry_token; char return_desc; unsigned char method_identity[32]; unsigned char owner_identity[32]; char *argument_tags; int argument_count; char *resource_path; unsigned char is_static; js_vm_symbol_cache_entry *symbols; int symbol_count; int symbol_capacity; struct js_vm_program *symbol_cache_owner; } js_vm_program;
typedef struct { jbyteArray bytes; jobject loader; } js_vm_loaded_resource;
typedef struct js_vm_ephemeral_cache_entry {
    jlong entry_token;
    char *resource_path;
    js_vm_program *program;
    struct js_vm_ephemeral_cache_entry *next;
} js_vm_ephemeral_cache_entry;

/*
 * One authenticated AKEN method frame prepared for repeated execution.  This
 * cache deliberately keeps only the parsed/prepared VM program plus public
 * binding digests.  It never owns the page frame, a DEK/key, a page nonce, or
 * any encoded payload bytes.  The loader global reference is the cache's
 * concrete class-loader binding; it is released when the entry is retired.
 *
 * active_users is bounded to one.  Resident opcode state is mutable during an
 * execution, so a second concurrent caller must miss the cache and prepare an
 * independent program instead of sharing that state.  retired entries remain
 * linked until their active lease is released, preventing clear/unload from
 * creating a use-after-free window.
 */
typedef struct js_vm_aken_cache_entry {
    jlong entry_token;
    jint page_index;
    uint32_t page_count;
    unsigned char encoded_handle_digest[32];
    unsigned char call_site_proof_digest[32];
    unsigned char artifact_commitment[32];
    unsigned char layout_digest[32];
    unsigned int session_generation;
    jobject loader_global;
    js_vm_program *program;
    unsigned int active_users;
    unsigned int retired;
    struct js_vm_aken_cache_entry *next;
} js_vm_aken_cache_entry;
typedef struct { int type; jint i; jlong l; jfloat f; jdouble d; jobject o; int uninit_id; const char *uninit_type; } js_vm_value;

/* Per-thread VM execution arena.  The arena owns only private, mutable
 * execution buffers; resident artifact state (constant pool, symbols and
 * operand storage) remains bound to the current program/session.  Frames are
 * acquired from a bounded pool in js_vm_core.c and are never shared by two
 * active executions. */
typedef struct js_vm_execution_frame {
    js_vm_insn *insns;
    js_vm_value *locals;
    js_vm_value *stack;
    jint *operand_scratch;
    size_t insn_capacity;
    size_t locals_capacity;
    size_t stack_capacity;
    size_t operand_capacity;
    unsigned int generation;
    unsigned int depth;
    unsigned int active;
    unsigned int tls_owned;
    unsigned int fallback_state_slot;
    uintptr_t owner_thread;
    const js_vm_program *owner_program;
} js_vm_execution_frame;

typedef struct { char *owner; char *name; char *desc; } js_vm_method_ref;
typedef struct { int ok; jobject value; } js_vm_object_result;

JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len);

#endif
