package io.github.hht0rro.javashroud.capabilities



import com.fasterxml.jackson.databind.node.JsonNodeFactory

import io.github.hht0rro.javashroud.model.schema.ParamSchema



internal fun loaderProtectionCapabilityBindings(): List<CapabilityBinding> = listOf(

    CapabilityBinding(

        id = "class-encryption-loader",

        name = "类加密装载器",

        description = "将选定 .class 主体加密存放到 JAR 资源中，由运行时自定义 ClassLoader 解密 defineClass。" +

            " 支持 AES-128/AES-256 加密策略，per-class 或 global 密钥模式，" +

            " 并注入反射调用防护和类加载完整性校验。",

        tagIds = listOf("loader-protection", "encryption"),

        stability = "experimental",

        risk = "high",

        requiresRuntimeFlags = emptyList(),

        compatibilityNotes = "会改变类加载路径并把类主体封装到加密资源；请重点验证反射、资源路径和自定义 ClassLoader 场景。",
        requiredPassIds = listOf("jni-microkernel-loader"),
        defaultEnabled = false,

        params = listOf(

            ParamSchema(

                key = "encryptionStrategy",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("aes-128"),

                options = listOf("aes-128", "aes-256"),

                description = "类主体加密算法。",

            ),

            ParamSchema(

                key = "keyMode",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("per-class"),

                options = listOf("per-class", "global"),

                description = "密钥作用域：per-class 为每个类生成独立密钥，global 为所有加密类共享一个密钥。",

            ),

            ParamSchema(

                key = "seed",

                type = "number",

                defaultValue = JsonNodeFactory.instance.nullNode(),

                options = null,

                description = "确定性种子，用于密钥生成和名称随机化。null 表示随机。",

            ),

        ),

    ),

    CapabilityBinding(

        id = "method-body-delayed-decryption",

        name = "方法体延迟解密",

        description = "保留类结构但将选定方法体搬入加密资源，首次调用时通过 hidden class 或运行时解密恢复方法体。" +

            " 支持 lazy-decrypt（首次调用时解密）和 hidden-class-redirect（跳转到 hidden class 实现）两种模式。",

        tagIds = listOf("loader-protection"),

        stability = "experimental",

        risk = "high",

        requiresRuntimeFlags = emptyList(),

        compatibilityNotes = "会改变方法体恢复和调用路径；hidden-class-redirect 模式需要 JDK 15+。",
        requiredPassIds = listOf("jni-microkernel-loader"),

        defaultEnabled = false,

        params = listOf(

            ParamSchema(

                key = "mode",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("lazy-decrypt"),

                options = listOf("lazy-decrypt", "hidden-class-redirect"),

                description = "解密模式：lazy-decrypt 首次调用时解密恢复，hidden-class-redirect 跳转到 hidden class。",

            ),

            ParamSchema(

                key = "encryptionStrategy",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("aes-128"),

                options = listOf("aes-128", "aes-256"),

                description = "方法体加密算法。",

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

)



fun buildLoaderProtectionCapabilityDefinitions() = capabilityDefinitions(loaderProtectionCapabilityBindings())
