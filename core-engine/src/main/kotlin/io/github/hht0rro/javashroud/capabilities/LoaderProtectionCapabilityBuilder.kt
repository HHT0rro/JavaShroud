package io.github.hht0rro.javashroud.capabilities



import com.fasterxml.jackson.databind.node.JsonNodeFactory

import io.github.hht0rro.javashroud.model.schema.ParamSchema



internal fun loaderProtectionCapabilityBindings(): List<CapabilityBinding> = listOf(

    CapabilityBinding(

        id = "class-encryption-loader",

        name = "类加密装载器",

        description = "将选定 .class 主体以认证加密资源存放，由运行时自定义 ClassLoader 解密 defineClass。" +

            " aes-128/aes-256 表示 AES-GCM 密钥长度；密钥从 sealed native runtime root 派生，" +

            " metadata、class name、resource path 和 sealing context 参与 AAD，认证失败时拒绝加载。",

        tagIds = listOf("loader-protection", "encryption"),

        stability = "experimental",

        risk = "high",

        requiresRuntimeFlags = emptyList(),

        compatibilityNotes = "需要 jni-microkernel-loader；native 不可用、metadata 篡改或资源篡改会 fail-closed。会改变类加载路径，请重点验证反射、资源路径和自定义 ClassLoader 场景。",
        requiredPassIds = listOf("jni-microkernel-loader"),
        defaultEnabled = false,

        params = listOf(

            ParamSchema(

                key = "encryptionStrategy",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("aes-128"),

                options = listOf("aes-128", "aes-256"),

                description = "类主体认证加密策略；aes-128/aes-256 表示 AES-GCM key size。",

            ),

            ParamSchema(

                key = "keyMode",

                type = "enum",

                defaultValue = JsonNodeFactory.instance.textNode("per-class"),

                options = listOf("per-class", "global"),

                description = "密钥作用域：per-class 为每个类生成独立派生材料，global 为所有加密类共享派生材料；作用域进入 AEAD AAD。",

            ),

            ParamSchema(

                key = "seed",

                type = "number",

                defaultValue = JsonNodeFactory.instance.nullNode(),

                options = null,

                description = "非秘密个性化种子，用于名称和 metadata 随机化；null 表示随机。",

            ),

        ),

    ),

    CapabilityBinding(

        id = "method-body-delayed-decryption",

        name = "方法体延迟解密",

        description = "保留类结构但将选定方法体搬入 AES-GCM 认证加密资源，调用时通过 hidden class 或运行时解密恢复方法体。" +

            " trampoline 只携带 v2 metadata，不携带 raw key；runtime 从 sealed native root 派生子密钥，认证失败时拒绝执行。",

        tagIds = listOf("loader-protection"),

        stability = "experimental",

        risk = "high",

        requiresRuntimeFlags = emptyList(),

        compatibilityNotes = "需要 jni-microkernel-loader；native 不可用、metadata 篡改或资源篡改会 fail-closed。会改变方法体恢复和调用路径；hidden-class-redirect 模式需要 JDK 15+。",
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

                description = "方法体认证加密策略；aes-128/aes-256 表示 AES-GCM key size。",

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
