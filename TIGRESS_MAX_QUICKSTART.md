# Tigress Max 档实施快速启动指南

## 当前状态
- 位置：E:\XiangMu\JavaShroud-public
- 完成度：50%（核心防护已实现）
- 剩余工作：多 dispatcher、stack/register、nested VM、bogus functions、多 profile 解码
- 测试状态：528 passed
- Goal：active，继续架构重构

## 立即开始实施

### Step 1: Phase 1 - 多 Dispatcher 形态（最高优先级）

#### 1.1 创建 Kotlin 端枚举（~5分钟）
文件：`core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/DispatcherProfile.kt`

```kotlin
package io.github.hht0rro.javashroud.transforms.protection

enum class DispatcherProfile {
    SWITCH,
    DIRECT_THREADED,
    INDIRECT_THREADED,
    CALL_THREADED,
    IF_NEST,
    INTERPOLATION;
    
    companion object {
        fun selectFromAuth(
            entryToken: ByteArray,
            resourcePath: String,
            manifestMesh: ByteArray
        ): DispatcherProfile {
            val hash = (entryToken + resourcePath.toByteArray() + manifestMesh)
                .fold(0L) { acc, b -> acc * 31 + b.toLong() }
            return values()[(hash % values().size).toInt().absoluteValue]
        }
    }
}
```

#### 1.2 创建 Native 端 Dispatcher 框架（~30分钟）
文件：`core-engine/src/main/native/js_vm_dispatcher.h`

```c
#ifndef JS_VM_DISPATCHER_H
#define JS_VM_DISPATCHER_H

#include <jni.h>
#include "js_vm_core.h"

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

// 获取 dispatcher 函数
dispatcher_fn js_vm_get_dispatcher(dispatcher_profile_t profile);

// 从 resource 读取 profile
dispatcher_profile_t js_vm_read_dispatcher_profile(js_vm_context_t* ctx);

// 验证 profile 认证
int js_vm_verify_dispatcher_auth(js_vm_context_t* ctx, dispatcher_profile_t profile);

#endif
```

#### 1.3 实现第一个 Dispatcher（switch）（~10分钟）
文件：`core-engine/src/main/native/js_vm_dispatcher.c`

将当前 `js_vm_execute` 的主循环提取为 `dispatch_switch`

#### 1.4 修改 js_vm_core.c（~10分钟）
重构 `js_vm_execute` 为 dispatcher 选择器

#### 1.5 构建和测试（~10分钟）
```
.\core-engine\build-native.bat
.\gradlew.bat :core-engine:test --tests "*Vm*"
```

### Step 2: 实现剩余 5 个 Dispatcher（~2小时）
按优先级：
1. INDIRECT_THREADED（函数指针表，最容易）
2. IF_NEST（二叉树，逻辑清晰）
3. DIRECT_THREADED（需要 GCC computed goto）
4. INTERPOLATION（插值搜索）
5. CALL_THREADED（最复杂）

### Step 3: Phase 2-6（后续）
参考 TIGRESS_MAX_TECHNICAL_SPEC.md

## 验证检查点
每完成一个 Phase：
1. 运行 `.\gradlew.bat :core-engine:test --tests "*Vm*"`
2. 确认测试通过
3. 运行 `.\core-engine\build-native.bat`
4. 确认编译成功

## 问题排查
- 编译错误：检查 native 头文件包含
- 链接错误：检查 build-native-kernel.bat 是否包含新文件
- 运行时错误：添加 native 日志输出

## 完成标志
Phase 1 完成标志：
- [x] 6 种 dispatcher 全部实现
- [x] Profile 认证机制就绪
- [x] 测试通过（至少 528+）
- [x] 发散测试验证（不同 profile）

## 预计时间
- Phase 1: 4-6 小时
- Phase 2: 3-4 小时
- Phase 3: 4-5 小时
- Phase 4: 3-4 小时
- Phase 5: 2-3 小时
- Phase 6: 2-3 小时
- **总计：18-25 小时实施时间**

## 立即行动
```powershell
cd E:\XiangMu\JavaShroud-public
# 创建 DispatcherProfile.kt
# 创建 js_vm_dispatcher.h
# 创建 js_vm_dispatcher.c
# 修改 js_vm_core.c
# 构建测试
```

开始实施！
