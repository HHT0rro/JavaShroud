package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ParamSchema

private fun fixedVbc4Invariant(key: String, description: String): ParamSchema = ParamSchema(
    key = key,
    type = "boolean",
    defaultValue = JsonNodeFactory.instance.booleanNode(true),
    options = null,
    description = description,
    hidden = true,
)

internal fun vmProtectionCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "method-virtualization",
        name = "方法级虚拟化",
        description = "将选定方法 lowering 为 VBC4-only native bytecode VM 资源，并通过 JNI native dispatcher 执行；旧版 VM 资源 fail-closed。",
        tagIds = listOf("vm-protection"),
        stability = "experimental",
        risk = "high",
        requiresRuntimeFlags = emptyList(),
        platformConstraints = emptyList(),
        compatibilityNotes = "VBC4-only 破坏性升级：要求 jni-microkernel-loader，旧资源、旧 profile 和低强度参数全部拒绝。",
        requiredPassIds = listOf("jni-microkernel-loader"),
        defaultEnabled = false,
        params = listOf(
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "非秘密个性化输入；输出仍由每产物 CSPRNG 材料随机化，不保证复现 VM key、布局、资源路径或 native profile。",
            ),
            ParamSchema(
                key = "methodSelection",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("critical-plus"),
                options = listOf("safe", "critical-auto", "critical-plus", "all-compatible"),
                description = "广义类规则的方法选择策略：safe 保留小型非覆盖方法选择；critical-auto 自动选择 VM 兼容且带字段、调用、类型、分支、异常或 invokedynamic 信号的关键方法；critical-plus 在 critical-auto 基础上额外纳入含分支或非平凡规模的纯计算方法；all-compatible 强制选择所有 VM 兼容方法。显式方法规则仍优先。",
            ),
            ParamSchema(
                key = "strictVirtualization",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(true),
                options = null,
                description = "严格虚拟化：对 methodSelection 选中的广义类规则方法和显式方法规则执行 fail-closed；构造器、类初始化器、abstract/native 方法除外。遇到当前 VBC4 不支持的字节码或超过 maxInstructions 时 fail-closed 报错，不再静默保留明文实现。预算外或未被 methodSelection 选中的广义类规则方法保持原样。显式方法规则仍优先。",
            ),
            ParamSchema(
                key = "maxInstructions",
                type = "number",
                defaultValue = JsonNodeFactory.instance.numberNode(99999),
                options = null,
                description = "单个方法允许虚拟化的最大字节码指令数；非严格模式下超过阈值保持原样，严格模式下超过阈值会报错。默认 99999，确保显式命中的大型 VBC4/热点方法不会因默认阈值被跳过。",
            ),
            ParamSchema(
                key = "maxBroadVirtualizedMethods",
                type = "number",
                defaultValue = JsonNodeFactory.instance.numberNode(99999),
                options = null,
                description = "广义类规则自动虚拟化的方法数量上限；默认 99999，用于保持 all-compatible/全量配置的最大覆盖语义。设置为 0 表示不限制，显式成员规则不受该上限约束。",
            ),
            ParamSchema(
                key = "highValueMethods",
                type = "string",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "critical-plus 高价值方法显式纳入名单，逗号/分号/换行分隔；项可写 methodName 或 owner#methodName:descriptor。显式成员规则仍优先。",
                hidden = true,
            ),
            ParamSchema(
                key = "highValueMethodDeny",
                type = "string",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "critical-plus 高价值自动选择排除名单，逗号/分号/换行分隔；项可写 methodName 或 owner#methodName:descriptor。用于排除误选热点方法，显式成员规则不受影响。",
                hidden = true,
            ),
            fixedVbc4Invariant("vbc4StateBoundEncoding", "VBC4 固定行为：state-bound encoding 始终启用，不能关闭。"),
            fixedVbc4Invariant("vbc4HandlerMorphing", "VBC4 固定行为：handler morphing 始终启用，不能关闭。"),
            fixedVbc4Invariant("vbc4StrengthMax", "VBC4 固定行为：强度固定为 max，不提供低强度或兼容 profile。"),
            fixedVbc4Invariant("vbc4InterpreterDiversity", "VBC4 固定行为：native-only 路径始终启用构建期解释器多样化，不能关闭。"),
            fixedVbc4Invariant("vbc4HashedJniSymbols", "VBC4 固定行为：JNI VM 调用目标使用 per-build/per-method token 定位，热路径不传递明文符号。"),
            fixedVbc4Invariant("vbc4ExecutableRegisterIr", "VBC4 固定行为：native dispatcher 以 register IR 为主执行，stack opcode 只作为兼容输入。"),
            fixedVbc4Invariant("vbc4SuperOperators", "VBC4 固定行为：serializer 按方法随机结构 seed 折叠 super-operator 并纳入认证状态。"),
            fixedVbc4Invariant("vbc4IntegrityKeyBinding", "VBC4 固定行为：session integrity digest 参与 seed unwrap、block key 和 CP key 派生。"),
            fixedVbc4Invariant("vbc4EphemeralRootMaterial", "VBC4 固定行为：native 根材料只按需短生命周期派生，用后擦除。"),
        ),
    ),
)

fun buildVmProtectionCapabilityDefinitions() = capabilityDefinitions(vmProtectionCapabilityBindings())
