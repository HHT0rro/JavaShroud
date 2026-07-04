# Tigress Max 档剩余功能技术规格书

## 当前状态总结
- 已完成：50% (核心防护：per-artifact/per-method/per-run 发散)
- 未完成：50% (多形态、嵌套、bogus 机制)
- 当前测试：528 passed
- 工作目录：E:\XiangMu\JavaShroud-public

## Phase 1: 多 Dispatcher 形态 - 技术规格

### 1.1 Kotlin 端改动

#### 文件：VmBytecodeSerializer.kt
添加 dispatcher profile 枚举和选择逻辑：

```kotlin
enum class DispatcherProfile {
    SWITCH,           // 当前 switch-case
    DIRECT_THREADED,  // computed goto
    INDIRECT_THREADED,// 函数指针表
    CALL_THREADED,    // 独立函数调用
    IF_NEST,          // 二叉 if-else
    INTERPOLATION     // 插值查找
}

// 基于 entry token + resource path + manifest mesh 派生
fun selectDispatcherProfile(
    entryToken: ByteArray,
    resourcePath: String,
    manifestMesh: ByteArray
): DispatcherProfile {
    val hash = (entryToken + resourcePath.toByteArray() + manifestMesh)
        .fold(0L) { acc, b -> acc * 31 + b }
    return DispatcherProfile.values()[(hash % 6).toInt().absoluteValue]
}
```

#### 文件：新增 DispatcherProfileCodec.kt
序列化 dispatcher profile 到 VMBC 资源：

```kotlin
object DispatcherProfileCodec {
    fun encodeProfile(profile: DispatcherProfile): Byte = profile.ordinal.toByte()
    fun writeToResource(profile: DispatcherProfile, output: DataOutputStream) {
        output.writeByte(0xD1) // profile marker
        output.writeByte(encodeProfile(profile))
    }
}
```

### 1.2 Native 端改动

#### 文件：js_vm_dispatcher.h (新建)
```c
typedef enum {
    DISPATCHER_SWITCH = 0,
    DISPATCHER_DIRECT_THREADED = 1,
    DISPATCHER_INDIRECT_THREADED = 2,
    DISPATCHER_CALL_THREADED = 3,
    DISPATCHER_IF_NEST = 4,
    DISPATCHER_INTERPOLATION = 5
} dispatcher_profile_t;

typedef jvalue (*vm_handler_fn)(JNIEnv*, js_vm_context_t*, const uint8_t*);

// Dispatcher 函数指针
typedef jvalue (*dispatcher_fn)(
    JNIEnv* env,
    js_vm_context_t* ctx,
    const uint8_t* program,
    uint32_t program_size,
    dispatcher_profile_t profile
);
```

#### 文件：js_vm_dispatcher.c (新建)
实现 6 种 dispatcher：

```c
// 1. Switch dispatcher (当前实现)
jvalue dispatch_switch(JNIEnv* env, js_vm_context_t* ctx, 
                       const uint8_t* program, uint32_t size,
                       dispatcher_profile_t profile) {
    uint32_t pc = 0;
    while (pc < size) {
        uint8_t opcode = program[pc++];
        switch (opcode) {
            case OP_LOAD: /* ... */ break;
            case OP_STORE: /* ... */ break;
            // ... 所有 opcodes
        }
    }
}

// 2. Direct threaded dispatcher
#ifdef __GNUC__
jvalue dispatch_direct_threaded(JNIEnv* env, js_vm_context_t* ctx,
                                const uint8_t* program, uint32_t size,
                                dispatcher_profile_t profile) {
    static void* dispatch_table[] = {
        &&label_OP_LOAD,
        &&label_OP_STORE,
        // ... 所有 labels
    };
    
    uint32_t pc = 0;
    #define DISPATCH() goto *dispatch_table[program[pc++]]
    
    DISPATCH();
    
    label_OP_LOAD:
        // handler code
        DISPATCH();
    
    label_OP_STORE:
        // handler code
        DISPATCH();
    
    // ... 所有 handlers
}
#endif

// 3. Indirect threaded dispatcher
jvalue dispatch_indirect_threaded(JNIEnv* env, js_vm_context_t* ctx,
                                  const uint8_t* program, uint32_t size,
                                  dispatcher_profile_t profile) {
    vm_handler_fn handlers[] = {
        handler_load,
        handler_store,
        // ... 所有 handler 函数
    };
    
    uint32_t pc = 0;
    while (pc < size) {
        uint8_t opcode = program[pc++];
        handlers[opcode](env, ctx, program + pc);
    }
}

// 4. Call threaded dispatcher
jvalue dispatch_call_threaded(JNIEnv* env, js_vm_context_t* ctx,
                              const uint8_t* program, uint32_t size,
                              dispatcher_profile_t profile) {
    // 每个 opcode 编译为函数调用序列
    // 需要预处理 program 为 call chain
}

// 5. If-nest dispatcher (二叉树)
jvalue dispatch_if_nest(JNIEnv* env, js_vm_context_t* ctx,
                        const uint8_t* program, uint32_t size,
                        dispatcher_profile_t profile) {
    uint32_t pc = 0;
    while (pc < size) {
        uint8_t opcode = program[pc++];
        if (opcode < 128) {
            if (opcode < 64) {
                if (opcode < 32) {
                    // ...
                }
            }
        } else {
            // ...
        }
    }
}

// 6. Interpolation dispatcher
jvalue dispatch_interpolation(JNIEnv* env, js_vm_context_t* ctx,
                               const uint8_t* program, uint32_t size,
                               dispatcher_profile_t profile) {
    // 插值搜索 + fallback to linear
}
```

#### 文件：js_vm_core.c 改动
重构 `js_vm_execute`：

```c
jvalue js_vm_execute(JNIEnv* env, js_vm_context_t* ctx,
                     const uint8_t* program, uint32_t program_size) {
    // 1. 从 resource 读取 dispatcher profile
    dispatcher_profile_t profile = read_dispatcher_profile(ctx);
    
    // 2. 验证 profile 认证 tag
    if (!verify_dispatcher_profile_auth(ctx, profile)) {
        return fail_closed_result();
    }
    
    // 3. 选择对应的 dispatcher
    dispatcher_fn dispatcher = get_dispatcher(profile);
    
    // 4. 执行
    return dispatcher(env, ctx, program, program_size, profile);
}

static dispatcher_fn get_dispatcher(dispatcher_profile_t profile) {
    switch (profile) {
        case DISPATCHER_SWITCH: return dispatch_switch;
        case DISPATCHER_DIRECT_THREADED: return dispatch_direct_threaded;
        case DISPATCHER_INDIRECT_THREADED: return dispatch_indirect_threaded;
        case DISPATCHER_CALL_THREADED: return dispatch_call_threaded;
        case DISPATCHER_IF_NEST: return dispatch_if_nest;
        case DISPATCHER_INTERPOLATION: return dispatch_interpolation;
        default: return NULL; // fail-closed
    }
}
```

### 1.3 验证计划
- 单元测试：每种 dispatcher 独立测试
- 集成测试：混合 dispatcher 的 JAR
- 发散测试：验证 profile 选择不稳定性

## Phase 2-6 技术规格（简要）

### Phase 2: Stack/Register 双模式
- 新增 `OperandMode` 枚举：REGISTER / STACK / MIXED
- Native 端实现 operand stack 操作
- 互斥条件：non-nested XOR nested

### Phase 3: 2 层 Nested VM
- 外层 VM：认证 + dispatch管理
- 内层 VM：真实执行
- VPC opaque化：state-bound update

### Phase 4: Bogus Functions
- 生成假 parser/decoder 函数
- Bogus handler rows 注入
- Bogus loop iterations

### Phase 5: 多 Profile 解码
- Tigress EncodeByteArray/ObfuscateDecodeByteArray
- Entry/path/profile 三重绑定

### Phase 6: 完整验收
- 所有 Tests And Acceptance 项

## 实施优先级
1. Phase 1（多 dispatcher）- 最关键，影响所有后续
2. Phase 2（stack/register）- 配合 Phase 1
3. Phase 3-4-5 并行
4. Phase 6 最终验收

## 文件清单

### 新建文件
- core-engine/src/main/kotlin/.../DispatcherProfileCodec.kt
- core-engine/src/main/native/js_vm_dispatcher.h
- core-engine/src/main/native/js_vm_dispatcher.c
- core-engine/src/main/native/js_vm_operand_stack.c
- core-engine/src/main/native/js_vm_nested.c
- core-engine/src/main/native/js_vm_bogus.c

### 修改文件
- core-engine/src/main/kotlin/.../VmBytecodeSerializer.kt
- core-engine/src/main/native/js_vm_core.c
- core-engine/src/main/native/js_vm_core.h
- core-engine/src/main/native/js_vm_resource.c
- core-engine/src/main/native/build-native-kernel.bat

## 下一步行动
在新的 goal session 中，从 Phase 1 开始逐步实施，每完成一个 Phase 运行测试验证后再继续。

