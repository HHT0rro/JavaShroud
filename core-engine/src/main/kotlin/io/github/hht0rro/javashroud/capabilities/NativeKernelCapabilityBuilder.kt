package io.github.hht0rro.javashroud.capabilities



import com.fasterxml.jackson.databind.node.JsonNodeFactory

import io.github.hht0rro.javashroud.model.schema.ParamSchema



private val jniMicrokernelAnchorPassIds = listOf(

    "anti-dump-protection",

    "anti-instrumentation",

    "anti-symbolic-execution",

    "callsite-rotation-protection",

    "class-encryption-loader",

    "environment-bound-keys",

    "exception-semantic-virtualization",

    "method-body-delayed-decryption",

    "method-virtualization",
    "string-encryption",

)



/**

 * Phase 4: High-cost protection kernel capabilities.

 *

 * These are advanced anti-tamper and anti-analysis capabilities that:

 * - Are only for user-owned JAR authorized protection scenarios

 * - Default to OFF

 * - Stay outside the default pipeline until explicitly selected by the user

 * - Include detailed risk, platform, and compatibility annotations

 */

internal fun nativeKernelCapabilityBindings(): List<CapabilityBinding> = listOf(

    CapabilityBinding(

        id = "anti-instrumentation",

        name = "反插桩保护",

        description = "检测 -javaagent、ByteBuddy、常见 JVMTI/instrumentation transform 和运行时 class retransformation，" +

            "并对 attach 痕迹进行探测，可选择记录、降级、拒绝或切换保护路径。",

        tagIds = listOf("native-kernel", "runtime-defense"),

        stability = "experimental",

        risk = "high",

        requiresRuntimeFlags = emptyList(),

        platformConstraints = emptyList(),

        compatibilityNotes = "可能与调试、测试、APM、游戏反作弊或监控工具冲突。仅用于授权保护场景。",

        requiredPassIds = listOf("jni-microkernel-loader"),

        defaultEnabled = false,

        params = listOf(

            ParamSchema(

                key = "detectionLevel",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("standard"),

                options = listOf("standard", "aggressive"),

                description = "检测级别：standard 检查 -javaagent 与 JVMTI；aggressive 额外增加 ByteBuddy/attach 检测。",

            ),

            ParamSchema(

                key = "response",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("log"),

                options = listOf("log", "degrade", "refuse", "switch-path"),

                description = "响应策略：log 仅记录；degrade 降低保护强度；refuse 拒绝运行；switch-path 切换保护路径。",

            ),

            ParamSchema(

                key = "seed",

                type = "number",

                defaultValue = JsonNodeFactory.instance.nullNode(),

                options = null,

                description = "确定性种子。",

            ),

        ),

    ),

    CapabilityBinding(

        id = "anti-dump-protection",

        name = "反内存转储",

        description = "通过 JNI/native 辅助降低 heap dump、class dump、hprof 等内存转储时的关键材料可见性。" +

            " field-scramble 是低强度 Java 字段扰动；jni-key-hold/full 依赖 native 可用性并在 native 缺失时 fail-closed。",

        tagIds = listOf("native-kernel", "runtime-defense"),

        stability = "experimental",

        risk = "high",

        requiresRuntimeFlags = emptyList(),

        platformConstraints = listOf("HotSpot JVM"),

        compatibilityNotes = "仅用于授权保护场景，可能与诊断、分析、heap 调试工具冲突。jni-key-hold/full 要求 jni-microkernel-loader 成功加载。",

        requiredPassIds = listOf("jni-microkernel-loader"),

        defaultEnabled = false,

        params = listOf(

            ParamSchema(

                key = "protectionLevel",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("field-scramble"),

                options = listOf("field-scramble", "jni-key-hold", "full"),

                description = "保护级别：field-scramble 为低强度字段扰动；jni-key-hold 将密钥持有在 JNI 层；full 启用 native 严格路径，native 不可用则拒绝。",

            ),

        ),

    ),

    CapabilityBinding(

        id = "jni-microkernel-loader",

        name = "JNI 微内核加载器",

        description = "将 loader、解密或 VM 解释器等高价值保护内核下沉到 JNI/native 层。" +

            "不将整个程序强制 native 化，只下沉保护核心。",

        tagIds = listOf("native-kernel"),

        stability = "experimental",

        risk = "high",

        requiresRuntimeFlags = emptyList(),

        platformConstraints = listOf("Windows x64", "Linux x64", "macOS x64/arm64"),

        compatibilityNotes = "需要平台特定 native 库。混淆时优先使用 JAVASHROUD_ZIG 或系统 PATH 中的 Zig；缺工具链时自动下载到用户目录 .javashroud/zig/0.13.0（Windows 形如 C:\\Users\\<用户名>\\.javashroud\\zig\\0.13.0）后重编译 native 微内核；失败则终止本次混淆，不使用预编译 native 回退路径。只能与类加密、方法虚拟化或其他需要运行时 helper 的 pass 一起启用，不能单独启用.",

        requiresAnyPassIds = jniMicrokernelAnchorPassIds,

        defaultEnabled = false,

        params = listOf(

            ParamSchema(

                key = "kernelComponents",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("loader"),

                options = listOf("loader", "decrypt", "vm", "guards", "all"),

                description = "下沉的内核组件。loader 保持默认兼容；decrypt、vm、guards 或 all 会随 JNI 微内核声明对应 native 能力。",

            ),

            ParamSchema(

                key = "targetPlatform",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("auto"),

                options = listOf("auto", "windows-x64", "linux-x64", "macos-x64", "macos-arm64"),

                description = "目标平台。",

            ),

            ParamSchema(

                key = "diversifiedVirtualization",

                type = "boolean",

                defaultValue = JsonNodeFactory.instance.booleanNode(true),

                options = null,

                description = "多样化虚拟化混淆：开启后，下沉到 native 内核的保护逻辑使用种子多样化的虚拟指令编码，" +

                    "同一逻辑在不同构建/种子下产生不同的虚拟指令字节但语义保持不变，提高静态去虚拟化难度。",

                hidden = true,

            ),

            ParamSchema(

                key = "nativeRecompilation",

                type = "boolean",

                defaultValue = JsonNodeFactory.instance.booleanNode(true),

                options = null,

                description = "混淆时编译：开启后优先使用 JAVASHROUD_ZIG 或系统 PATH 中的 Zig；缺失时自动下载到用户目录 .javashroud/zig/0.13.0（Windows 形如 C:\\Users\\<用户名>\\.javashroud\\zig\\0.13.0），" +

                    "再从内置 C 源码重编译 native 微内核；该选项必须开启，工具链获取失败或编译失败时终止本次混淆，不使用预编译 native 回退路径。",

                hidden = false,

            ),

            ParamSchema(

                key = "nativeProtectionLevel",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("standard"),

                options = listOf("standard", "aggressive"),

                description = "native 反逆向保护级别。standard 包含反调试、源码多样化重编译与反反汇编 guard；" +

                    "aggressive 额外启用反虚拟机检测、完整性自校验和反脱壳保护。",

                hidden = true,

            ),

            ParamSchema(

                key = "seed",

                type = "number",

                defaultValue = JsonNodeFactory.instance.nullNode(),

                options = null,

                description = "确定性种子，控制 native 微内核多样化编码。",

            ),

        ),

    ),

)



fun buildNativeKernelCapabilityDefinitions() = capabilityDefinitions(nativeKernelCapabilityBindings())
