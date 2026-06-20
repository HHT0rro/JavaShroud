package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.transforms.encryption.encryptStrings
import io.github.hht0rro.javashroud.transforms.encryption.encryptFieldStringValues
import io.github.hht0rro.javashroud.transforms.hiding.hideMembers
import io.github.hht0rro.javashroud.transforms.metadata.stripCompileDebugInfo
import io.github.hht0rro.javashroud.transforms.obfuscation.applyControlFlowObfuscation
import io.github.hht0rro.javashroud.transforms.obfuscation.applyControlFlowFlattening
import io.github.hht0rro.javashroud.transforms.obfuscation.applyReferenceProxy
import io.github.hht0rro.javashroud.transforms.obfuscation.insertAntiDecompiler
import io.github.hht0rro.javashroud.transforms.obfuscation.invokeDynamicIndirect
import io.github.hht0rro.javashroud.transforms.obfuscation.obfuscateIntConstants
import io.github.hht0rro.javashroud.transforms.obfuscation.perturbStaticInit
import io.github.hht0rro.javashroud.transforms.rename.renameClasses
import io.github.hht0rro.javashroud.transforms.rename.renameFields
import io.github.hht0rro.javashroud.transforms.rename.renameMethods
import io.github.hht0rro.javashroud.transforms.rename.renamePackages
import io.github.hht0rro.javashroud.transforms.obfuscation.applyCondyIndirection

// Phase 1: Protection transforms
import io.github.hht0rro.javashroud.transforms.protection.applyClassEncryptionLoader
import io.github.hht0rro.javashroud.transforms.protection.applyMethodBodyDelayedDecryption

// Phase 2: VM protection transforms
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization

// Phase 3: Runtime defense transforms
import io.github.hht0rro.javashroud.transforms.protection.applyCallsiteRotationProtection
import io.github.hht0rro.javashroud.transforms.protection.applyEnvironmentBoundKeys
import io.github.hht0rro.javashroud.transforms.protection.applyAntiSymbolicExecution

// Phase 4: Native kernel transforms
import io.github.hht0rro.javashroud.transforms.protection.applyAntiInstrumentation
import io.github.hht0rro.javashroud.transforms.protection.applyAntiDumpProtection
import io.github.hht0rro.javashroud.transforms.protection.applyJniMicrokernelLoader
import io.github.hht0rro.javashroud.transforms.protection.applyExceptionSemanticVirtualization

internal fun metadataModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "strip-compile-debug-info", transform = ModuleTransform(::stripCompileDebugInfo)),
)

internal fun renamingModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "rename-classes", transform = ModuleTransform(::renameClasses)),
    ModuleBinding(id = "rename-packages", transform = ModuleTransform(::renamePackages)),
    ModuleBinding(id = "rename-methods", transform = ModuleTransform(::renameMethods)),
    ModuleBinding(id = "rename-fields", transform = ModuleTransform(::renameFields)),
)

internal fun encryptionModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "string-encryption", transform = ModuleTransform(::encryptStrings)),
    ModuleBinding(id = "field-string-encryption", transform = ModuleTransform(::encryptFieldStringValues)),
)

internal fun obfuscationModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "integer-constant-obfuscation", transform = ModuleTransform(::obfuscateIntConstants)),
    ModuleBinding(id = "static-init-perturbation", transform = ModuleTransform(::perturbStaticInit)),
    ModuleBinding(id = "anti-decompiler-structure", transform = ModuleTransform(::insertAntiDecompiler)),
    ModuleBinding(id = "invoke-dynamic-indirection", transform = ModuleTransform(::invokeDynamicIndirect)),
    ModuleBinding(id = "control-flow-obfuscation", transform = ModuleTransform(::applyControlFlowObfuscation)),
    ModuleBinding(id = "reference-proxy", transform = ModuleTransform(::applyReferenceProxy)),
    ModuleBinding(id = "control-flow-flattening", transform = ModuleTransform(::applyControlFlowFlattening)),
    ModuleBinding(id = "condy-constant-indirection", transform = ModuleTransform(::applyCondyIndirection)),
)

internal fun hidingModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "member-hide", transform = ModuleTransform(::hideMembers)),
)

// --- Phase 1: Loader protection ---

internal fun loaderProtectionModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "class-encryption-loader", transform = ModuleTransform(::applyClassEncryptionLoader)),
    ModuleBinding(id = "method-body-delayed-decryption", transform = ModuleTransform(::applyMethodBodyDelayedDecryption)),
)

// --- Phase 1: Helper deployment ---

internal fun helperDeploymentModuleBindings(): List<ModuleBinding> = emptyList()


// --- Phase 2: VM protection ---

internal fun vmProtectionModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "method-virtualization", transform = ModuleTransform(::applyMethodVirtualization)),
)

// --- Phase 3: Runtime defense ---

internal fun runtimeDefenseModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "callsite-rotation-protection", transform = ModuleTransform(::applyCallsiteRotationProtection)),
    ModuleBinding(id = "environment-bound-keys", transform = ModuleTransform(::applyEnvironmentBoundKeys)),
    ModuleBinding(id = "anti-symbolic-execution", transform = ModuleTransform(::applyAntiSymbolicExecution)),
    ModuleBinding(id = "exception-semantic-virtualization", transform = ModuleTransform(::applyExceptionSemanticVirtualization)),
)

// --- Phase 4: Native kernel ---

internal fun nativeKernelModuleBindings(): List<ModuleBinding> = listOf(
    ModuleBinding(id = "anti-instrumentation", transform = ModuleTransform(::applyAntiInstrumentation)),
    ModuleBinding(id = "anti-dump-protection", transform = ModuleTransform(::applyAntiDumpProtection)),
    ModuleBinding(id = "jni-microkernel-loader", transform = ModuleTransform(::applyJniMicrokernelLoader)),
)
