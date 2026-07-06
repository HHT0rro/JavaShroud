# Tigress Max 档剩余功能技术规格书

## Native Max Stub Shell 当前实现边界（2026-07-07）

本轮已把 `nativePackingLevel` 固化为 `off|standard|max` 三档协议边界：

- `off`：保持 Zig 编译出的 native 产物原样。
- `standard`：保留可加载动态库前缀，只追加认证 overlay，作为兼容档；不得被描述为真壳。
- `max`：生成外层 stub shell 动态库，并把 `.jsx` section sealing 之后的完整 inner `js_kernel` 作为认证编码 payload 写入 `js_shell_payload.inc`。Kotlin 构建链已接入 inner kernel -> payload bundle -> outer stub 编译路径，JAR 只应打包 outer `js_kernel_<platform>` 资源。

已落地的可验证证据边界：

- `NativeKernelShellPacker` 已新增 max payload header、nonce、layout profile、dispatcher profile、section digest、payload MAC、stub/payload binding tag、stored size、compression codec、chunk size/count 和 per-chunk native tag。max payload 现在默认尝试使用已有 `Vbc4ZstdCodec` 生成 zstd frame；只有压缩后不更小时才保留 raw stored payload，随后统一执行分块编码和每块 tag 校验。parser/MAC/chunk tag 篡改测试已覆盖。
- ABI probe 已收紧：只含 `JS_NATIVE_SHELL_LOADER_V1` 的 standard overlay marker 不能作为 max 真壳证据；max stub 必须同时包含 `JNI_OnLoad`、`JS_NATIVE_MAX_STUB_V1`、`JS_NATIVE_MAX_PAYLOAD_V1`。
- schema/前端展示边界已同步：`jni-microkernel-loader.nativePackingLevel` 默认值为 `max`，选项保留 `off|standard|max`；schema 描述与桌面端本地化文案均明确 `standard` 是兼容 overlay、不是 max 真壳，`max` 才是保护完整 `js_kernel` 的 outer stub shell。`nativeProtectionLevel=aggressive` 仍表示 native guard surface 增强，可与 `nativePackingLevel=max` 叠加但不替代 shell packing。
- 新增 `js_shell_stub.c/.h`、`js_shell_crypto.c/.h`、`js_shell_loader.h`、`js_shell_loader_pe.c`、`js_shell_loader_elf.c`、`js_shell_loader_macho.c`，并已纳入 Gradle native-src 资源打包。
- stub 已具备 native-side payload marker 校验、stream key MAC 校验、header 元数据一致性校验、per-chunk tag 校验、分块解码、zstd 解压和 decoded original payload 传递给 loader 的路径；Kotlin 侧生成的 `js_shell_payload_mac`/`js_shell_stream_key`/chunk tags 与 C stub 算法一致。`compileShellStubWithZig` 已把仓库内 bundled zstd decompressor 源码和 include 路径纳入 outer stub 编译，不引入新的第三方库。
- Linux `js_shell_loader_elf.c` 已从骨架推进到 ELF64 x86_64 匿名内存 loader：校验 ET_DYN/PT_LOAD/PT_DYNAMIC，匿名 `mmap`，处理核心 RELA relocation、GOT/PLT、host symbol lookup、`DT_INIT`、init array 和 `JNI_OnLoad` export 解析。Linux 手工映射路径已补齐 protected `.jsx` section 解封 fallback：当 inner ELF 不是由动态链接器注册、`dladdr` 无法给出正确 `dli_fbase` 时，`js_protected_section_unseal_now()` 会在 `/proc/self/maps` 标明的可读连续映射范围内从 seal marker 向下扫描 ELF64 `ET_DYN` header，并用 packer 写入的 `section_rva` 定位 `.jsx`，避免真实 JAR 在 `nativeDeriveClassEncryptionKey` 入口执行仍加密字节导致 `SIGILL`。当前 Linux focused artifact 验收与真实 JAR fixture 均已通过。
- Linux max artifact 已补充逆向指标型回归：测试先以 `nativePackingLevel=off` 产出 sealed inner kernel，再以 `nativePackingLevel=max` 产出 outer stub，并在 outer stub 中验证 max marker、standard overlay 排除、inner ELF header 不以 raw 动态库头形式直嵌、inner kernel 高熵 512-byte 明文片段抽样未命中、`JS_NATIVE_MAX_PAYLOAD_V1` marker 唯一，以及 `JniMicrokernelHelper` JNI/native 方法名和 VM/protected-section inner symbol 不以 ASCII 明文暴露。`native-max-reverse-evidence.md` 现在还写出四平台 JAR native entry 清单、outer stub/standard overlay entry 计数、文件 magic、printable ASCII token 摘要、可疑 printable token 命中和本机 `strings`/`readelf`/`nm`/`dumpbin` 工具可用性；该报告已形成自动化可审阅证据包，但若发布环境具备外部逆向工具，仍应补充真实工具输出而不是只记录 tool unavailable。
- 真实 JAR 运行态 fail-closed 已补充 payload/header、sealed bootstrap native index、max native shell resource path、VM preload profile tag、VM preload mesh binding 五类篡改验收：测试先生成可运行的 `nativePackingLevel=max` transformed JAR，验证 stdout 和退出码保持基线；随后分别复制 JAR 并翻转 max native shell payload/header 区域字节、翻转 `JSBI` sealed bootstrap native index envelope 字节、重命名 max outer stub resource entry 使 bootstrap index 指向缺失路径、重写 sealed VM preload index 中的 profile 字段、重写 sealed VM preload index 中的 mesh 字段，再运行篡改 JAR，要求不能保持原始业务输出，并且输出中出现 native loading/verification fail-closed 迹象。该证据覆盖真实 JAR 层面的 payload/header、bootstrap index、resource path、profile tag 与 mesh binding 篡改闭环。
- `JniMicrokernelHelper` 在调用 `nativePreloadRuntimeResources()` 前增加 sealed VM preload index 预检：只在该预检路径中解 runtime resource envelope 与项目内 raw/RLE zstd frame，随后解 `JSMI2` mask，并按 `jsmi2-entry-auth(token, sealedResource, sealedManifest, shardCount, mesh, profile)` 重算每条新格式 preload entry 的 auth tag。profile 或 mesh 被篡改时会在进入 native preload 前抛出 `SecurityException("invalid VM preload profile auth")`，避免 tainted mesh/profile 先污染 native call gate 或 JVM 状态；公开 `decodeRuntimeResourceForNative` 保持原有非压缩解码语义，避免影响 native 自己的 resource decode/reassemble 路径。
- Profile-bound shell 证据已补充到 `NativeKernelShellPackerTest` 和真实 JAR 回归：layout profile 与 dispatcher profile 同时写入 header、参与 payload MAC、参与分块 decode/tag 派生；篡改 header profile 会导致 max payload MAC 失败，篡改 bundle/profile 宏侧元数据会导致 per-chunk tag 验证失败；真实 JAR 侧的 VM preload profile/mesh 篡改也已进入运行态 fail-closed 验收，从协议层和运行层同时证明 profile/mesh mismatch 不能被当作无害元数据忽略。
- Windows `js_shell_loader_pe.c` 已从骨架推进到 PE64 manual mapper：校验 AMD64 DLL、映射 sections、DIR64 relocation、import resolution、entrypoint process attach、export lookup、`JNI_OnLoad` 转发和 inner `js_native_abi_table_v1` 解析。当前 Windows 策略把 manual-mapped inner PE 视为 process-lifetime image：只运行必要的 process attach，不运行 OS loader 未注册模块的 detach/unload/free 路径，不调用 inner `JNI_OnUnload`，也不释放可能仍被 JVM native entry 间接使用的 executable pages；inner kernel 必要初始化由导出的 `JNI_OnLoad` 显式完成，包括 `.jsx` 解封。为避免 HotSpot/JIT 将 native method 表直接绑定到非 OS-loader-owned manual-mapped image，inner kernel 现在导出 `js_native_abi_table_v1`，outer stub 在 inner `JNI_OnLoad` 完成后重新 `RegisterNatives`，把 `JniMicrokernelHelper` 的核心 native 方法完整注册到 outer stub 内的稳定 trampoline；trampoline 再转发到 inner ABI 表。这样保持 Java 层无解密 fallback、inner payload 仍内存加载，同时 JVM 看到的公开 native entry 位于正常 `System.load` 的 outer DLL。Windows inner PE 的少量 VM 缓存已避免依赖 loader-managed static TLS，以规避 manual-map TLS/CRT shutdown 边界导致的 `0xC0000374` heap corruption。`RealJniMicrokernelFixtureRegressionTest.jni_microkernel_loader_preserves_real_demo_and_complex_business_fixtures` 已在 Windows 本机连续两次强制重跑通过，证明真实 JAR 的 stdout 与退出码保持一致，并覆盖 payload/header、bootstrap index、resource path、VM preload profile 与 mesh 篡改 fail-closed；本次修复后未产生新的 `hs_err_pid*.log`。
- macOS `js_shell_loader_macho.c` 已从空骨架推进到 Mach-O 64 dylib 解析型 fail-closed：校验 x64/arm64、segment、dyld info、rebase/bind/lazy-bind 范围、`_JNI_OnLoad` export trie 和 `_js_native_abi_table_v1` export trie，但匿名执行映射仍明确 fail-closed。当前已新增 artifact 级验收：`macos-x64` 与 `macos-arm64` 均可交叉产出 max outer stub，产物包含 `JNI_OnLoad`、`JS_NATIVE_MAX_STUB_V1`、`JS_NATIVE_MAX_PAYLOAD_V1`，不含 standard overlay marker，并保留明确的 Mach-O anonymous execution fail-closed reason。README 或宣传文案不得把 macOS 完整内存加载器写成已完成。

本轮重跑验证（2026-07-07，Windows 主机）：`RealJniMicrokernelFixtureRegressionTest.jni_microkernel_loader_preserves_real_demo_and_complex_business_fixtures` 连续两次强制重跑均 `BUILD SUCCESSFUL`，覆盖真实 JAR 正常运行、stdout/退出码保持一致，以及 max native shell payload/header、sealed bootstrap native index、max native shell resource path、VM preload profile tag、VM preload mesh binding 五类篡改运行态 fail-closed；随后组合回归 `NativeKernelShellPackerTest` XML 结果为 9 tests / 0 failures / 0 errors，覆盖 max payload header/parser/MAC、profile-bound header MAC、per-chunk tag mismatch 与 standard overlay 篡改边界；`NativeRecompilationTransformsTest.native_max_reverse_evidence_report_is_written_for_outer_stubs` XML 结果为 1 test / 0 failures / 0 errors，并刷新 `build/core-engine/reports/native-max/native-max-reverse-evidence.md`：报告中 `META-INF/js-native/js_kernel_{linux,windows,macos}` entry 数为 4、outer stub entry 数为 4、standard overlay entry 数为 0，四平台均记录 SHA-256、文件 magic、max marker、敏感明文命中、printable token 摘要和工具可用性。`SchemaCapabilitiesTest.jni_microkernel_loader_schema_exposes_native_recompilation_params` XML 结果为 1 test / 0 failures / 0 errors，验证 `nativePackingLevel=max` 默认值、`off|standard|max` 选项、standard overlay 与 max stub shell 描述、完整 `js_kernel` 保护声明；桌面端 `corepack yarn build` 通过，确认新增前端本地化文案没有破坏构建。其中 Linux artifact 测试覆盖 inner ELF header 不 raw 直嵌、payload marker 唯一、敏感 JNI/helper/native symbol ASCII 明文不暴露，macOS artifact 测试覆盖 `macos-x64`/`macos-arm64` outer stub 形态与显式 fail-closed reason。

## 剩余验收边界
- macOS 仍是 Mach-O 解析型 fail-closed skeleton，尚未完成匿名执行映射、initializer 调用和真实 macOS 运行验收；任何 README 或宣传文案都不得宣称 macOS 完整内存加载器已完成。
- Linux 真实 JAR 在当前工作区的自动化回归已由前序 Ubuntu-24.04 + JDK21 记录证明过，但本机本轮只复跑了 Windows 主机上的 cross/artifact 与真实 Windows JAR 验收；最终发布前仍应在 Linux 主机重新跑真实 JAR，避免把旧环境证据当成当前发布证据。
- 逆向指标目前已有自动化 plaintext/string/header 抽样、JAR native entry 清单、文件 magic、printable token 摘要和工具可用性记录；发布验收若能在目标环境安装或调用 `readelf`/`nm`/`strings`/`dumpbin`，仍应补齐外部工具真实输出，避免只有内部扫描证据。
- 多线程压力、长生命周期 JVM、多次加载/卸载边界尚未作为独立验收矩阵覆盖；Windows 当前采用 process-lifetime manual image + outer trampoline 策略，发布文档应保留该生命周期边界。

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
