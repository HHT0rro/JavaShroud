#ifndef JS_VM_INTERNAL_H
#define JS_VM_INTERNAL_H

#include "js_native_common.h"

#define JS_VM_CP_STRING 1
#define JS_VM_CP_INT 2
#define JS_VM_CP_LONG 3
#define JS_VM_CP_FLOAT 4
#define JS_VM_CP_DOUBLE 5

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
    unsigned long long class_hash;
    unsigned long long meth_hash;
    unsigned long long sig_hash;
    char *type_name;
} js_vm_symbol_cache_entry;
typedef struct js_vm_program { js_vm_cp *cp; int cp_count; js_vm_insn *insns; int insn_count; int borrowed_insns; int borrowed_insn_operands; int cached_execution_ready; js_vm_reg_program reg_program; js_vm_exception *exceptions; int exception_count; int max_stack; int max_locals; int mac_key; int build_seed; int key_mask; uint32_t resident_rotation_epoch; unsigned char nonce[16]; int metadata_cp_index; uint32_t method_local_profile; uint32_t vbc4_flags; uint32_t nested_vm_profile; jlong entry_token; char return_desc; char *original_owner; char *original_name; char *original_desc; unsigned long long original_owner_hash; unsigned long long original_name_hash; unsigned long long original_desc_hash; uint32_t original_access; js_vm_symbol_cache_entry *symbols; int symbol_count; } js_vm_program;
typedef struct { jbyteArray bytes; jobject loader; } js_vm_loaded_resource;
typedef struct js_vm_ephemeral_cache_entry {
    jlong entry_token;
    char *resource_path;
    js_vm_program *program;
    struct js_vm_ephemeral_cache_entry *next;
} js_vm_ephemeral_cache_entry;
typedef struct { int type; jint i; jlong l; jfloat f; jdouble d; jobject o; int uninit_id; const char *uninit_type; } js_vm_value;
typedef struct { char *owner; char *name; char *desc; } js_vm_method_ref;
typedef struct { int ok; jobject value; } js_vm_object_result;

JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len);

#endif
