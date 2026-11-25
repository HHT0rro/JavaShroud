package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.model.schema.ModuleTagDefinition

fun buildCapabilityTagDefinitions(): List<ModuleTagDefinition> = listOf(
    ModuleTagDefinition(
        id = "metadata",
        name = "元数据混淆",
        description = "影响调试信息与类元数据可见性的混淆模块。",
        order = 10,
    ),
    ModuleTagDefinition(
        id = "renaming",
        name = "命名混淆",
        description = "影响类名、包名、字段名、方法名和参数名的混淆模块。",
        order = 20,
    ),
    ModuleTagDefinition(
        id = "encryption",
        name = "加密混淆",
        description = "对字符串、常量、数组等数据执行加密变换的混淆模块。",
        order = 30,
    ),
    ModuleTagDefinition(
        id = "obfuscation",
        name = "结构混淆",
        description = "对控制流、常量、指令序列等进行结构扰动的混淆模块。",
        order = 40,
    ),
    ModuleTagDefinition(
        id = "hiding",
        name = "隐藏混淆",
        description = "通过 synthetic/bridge 等标记隐藏成员以干扰反编译器与工具展示。",
        order = 50,
    ),
    ModuleTagDefinition(
        id = "loader-protection",
        name = "加载器保护",
        description = "类加密装载、方法体延迟解密、自定义 ClassLoader 部署等加载时保护模块。",
        order = 60,
    ),
    ModuleTagDefinition(
        id = "helper-deployment",
        name = "Helper 部署",
        description = "隐藏类部署、helper 指纹随机化、运行时 helper 注入等模块。",
        order = 70,
    ),
    ModuleTagDefinition(
        id = "runtime-defense",
        name = "运行时防御",
        description = "调用点轮换、环境绑定、反 dump、反调试、多版本人格切换等运行时保护模块。",
        order = 80,
    ),
    ModuleTagDefinition(
        id = "vm-protection",
        name = "虚拟化保护",
        description = "方法级虚拟化、基础块局部虚拟化、多方言 VM 轮换等虚拟化保护模块。",
        order = 90,
    ),
    ModuleTagDefinition(
        id = "aggressive",
        name = "激进混淆",
        description = "利用 JVM 验证器绕过的激进混淆模块，产物需要 -noverify 启动。",
        order = 110,
    ),
    ModuleTagDefinition(
        id = "native-kernel",
        name = "Native 内核",
        description = "JNI/native 微内核协处理模块，需要平台特定原生库支持。",
        order = 120,
    ),
)

internal fun sortedCapabilityTagDefinitions(): List<ModuleTagDefinition> =
    buildCapabilityTagDefinitions().sortedBy { tag: ModuleTagDefinition -> tag.order }
