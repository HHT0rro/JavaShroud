package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.currentVbc4BuildContextOrNull
import io.github.hht0rro.javashroud.transforms.rename.FIELD_RENAME_BINDINGS_RESOURCE
import io.github.hht0rro.javashroud.transforms.rename.METHOD_RENAME_BINDINGS_RESOURCE
import java.security.MessageDigest
import java.security.SecureRandom
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode

internal object HardenedArtifactFinalizer {
    fun finalizeForWrite(artifact: BytecodeArtifact, config: ObfuscationConfig): BytecodeArtifact {
        val profile = config.protectionProfile
        val draft = captureRenameDraft(artifact)
        currentVbc4BuildContextOrNull()?.publishSignedDebugMapDraft(draft)
        var next = artifact
        if (profile != HardenedProtectionProfile.MINIMAL) {
            val key = indyKey()
            val digest = artifactDigest(next)
            next = injectIndyBootstrap(next, key)
            next = IndyTargetRewriter.wrapBusinessHandles(next, key, digest)
        }
        return next
    }

    private fun captureRenameDraft(artifact: BytecodeArtifact): SignedDebugMap.Draft {
        fun parse(resource: String): List<SignedDebugMap.MemberMapping> {
            val entry = artifact.jarEntries.firstOrNull { it.name == resource } ?: return emptyList()
            return entry.bytes.toString(Charsets.UTF_8).lineSequence().mapNotNull { line ->
                val parts = line.split('|')
                if (parts.size != 4) null else SignedDebugMap.MemberMapping(parts[0], parts[1], parts[2], parts[3])
            }.toList()
        }
        return SignedDebugMap.Draft(
            methodMappings = parse(METHOD_RENAME_BINDINGS_RESOURCE),
            fieldMappings = parse(FIELD_RENAME_BINDINGS_RESOURCE),
            transformVersion = ProtectionFormat.CURRENT,
            buildId = currentVbc4BuildContextOrNull()?.nativeSeed?.toString(16) ?: "build",
        )
    }

    private fun indyKey(): ByteArray {
        val context = currentVbc4BuildContextOrNull()
        if (context != null) {
            val material = context.copyMasterKey()
            try {
                return MessageDigest.getInstance("SHA-256").digest(material + "indy-token-key-r1".toByteArray()).copyOf(16)
            } finally {
                material.fill(0)
            }
        }
        return ByteArray(16).also { SecureRandom().nextBytes(it) }
    }

    private fun artifactDigest(artifact: BytecodeArtifact): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(ProtectionFormat.CURRENT.toByteArray())
        artifact.classArtifacts.sortedBy { it.entryName }.forEach { classArtifact ->
            digest.update(classArtifact.entryName.toByteArray())
            digest.update(classArtifact.bytes)
        }
        return digest.digest()
    }

    private fun injectIndyBootstrap(artifact: BytecodeArtifact, key: ByteArray): BytecodeArtifact {
        val internalName = IndyTargetRewriter.BOOTSTRAP_OWNER
        val entryName = internalName + ".class"
        // RuntimeArtifactSealing may already have relocated the production
        // bootstrap and rewritten helpers (for example CallsiteRotationHelper)
        // to call that relocated owner. Patch every class that still carries
        // the four bootstrap key sentinels before adding the final wrapper
        // owner; otherwise the wrapper and the relocated resolver use different
        // AES-GCM keys and fail at the first business invokedynamic call site.
        val patchedArtifact = patchRelocatedIndyBootstrapOwners(artifact, key)
        val existing = patchedArtifact.classArtifacts.firstOrNull { it.summary.internalName == internalName }
        if (existing != null) {
            val patchedExisting = patchKeyLanes(existing.bytes, key)
            if (patchedExisting.contentEquals(existing.bytes)) return patchedArtifact
            val updatedClass = existing.copy(bytes = patchedExisting, summary = analyzeClassBytes(patchedExisting))
            val classArtifacts = patchedArtifact.classArtifacts.map { if (it.summary.internalName == internalName) updatedClass else it }
            val jarEntries = patchedArtifact.jarEntries.map { if (it.name == entryName) it.copy(bytes = patchedExisting) else it }
            return patchedArtifact.copy(
                jarEntries = jarEntries,
                classArtifacts = classArtifacts,
                classArtifactIndex = classArtifactIndex(classArtifacts),
            )
        }
        val resource = "/" + entryName
        val raw = HardenedArtifactFinalizer::class.java.getResourceAsStream(resource)?.readBytes()
            ?: return patchedArtifact
        val patched = patchKeyLanes(raw, key)
        val summary = analyzeClassBytes(patched)
        val classArtifact = ClassArtifact(entryName, summary, patched)
        val classArtifacts = patchedArtifact.classArtifacts + classArtifact
        val jarEntries = patchedArtifact.jarEntries + JarEntryData(entryName, patched)
        return patchedArtifact.copy(
            jarEntries = jarEntries,
            classArtifacts = classArtifacts,
            classArtifactIndex = classArtifactIndex(classArtifacts),
        )
    }

    private fun patchRelocatedIndyBootstrapOwners(
        artifact: BytecodeArtifact,
        key: ByteArray,
    ): BytecodeArtifact {
        var changed = false
        val classArtifacts = artifact.classArtifacts.map { classArtifact ->
            if (!hasIndyBootstrapKeySentinels(classArtifact.bytes)) return@map classArtifact
            val patched = patchKeyLanesBinary(classArtifact.bytes, key)
            if (patched.contentEquals(classArtifact.bytes)) return@map classArtifact
            changed = true
            classArtifact.copy(bytes = patched, summary = analyzeClassBytes(patched))
        }
        if (!changed) return artifact
        val byEntry = classArtifacts.associateBy { it.entryName }
        val jarEntries = artifact.jarEntries.map { entry ->
            byEntry[entry.name]?.let { updated -> entry.copy(bytes = updated.bytes) } ?: entry
        }
        return artifact.copy(
            jarEntries = jarEntries,
            classArtifacts = classArtifacts,
            classArtifactIndex = classArtifactIndex(classArtifacts),
        )
    }

    private fun hasIndyBootstrapKeySentinels(classBytes: ByteArray): Boolean =
        (0 until 4).all { lane ->
            val sentinel = 0x4A535230 + lane
            indexOfBytes(
                classBytes,
                byteArrayOf(
                    ((sentinel ushr 24) and 0xFF).toByte(),
                    ((sentinel ushr 16) and 0xFF).toByte(),
                    ((sentinel ushr 8) and 0xFF).toByte(),
                    (sentinel and 0xFF).toByte(),
                ),
            ) >= 0
        }

    private fun patchKeyLanes(classBytes: ByteArray, key: ByteArray): ByteArray {
        val node = ClassNode()
        ClassReader(classBytes).accept(node, 0)
        val clinit = node.methods.firstOrNull { it.name == "<clinit>" } ?: return classBytes
        var lane = 0
        clinit.instructions.toArray().forEach { insn ->
            if (lane >= 4) return@forEach
            val value = ((key[lane * 4].toInt() and 0xFF) shl 24) or
                ((key[lane * 4 + 1].toInt() and 0xFF) shl 16) or
                ((key[lane * 4 + 2].toInt() and 0xFF) shl 8) or
                (key[lane * 4 + 3].toInt() and 0xFF)
            val sentinel = 0x4A535230 + lane
            when (insn) {
                is LdcInsnNode -> {
                    val cst = insn.cst
                    if (cst is Number && cst.toInt() == sentinel) {
                        insn.cst = value
                        lane++
                    }
                }
            }
        }
        val writer = ClassWriter(0)
        node.accept(writer)
        var out = writer.toByteArray()
        if (lane < 4) {
            out = patchKeyLanesBinary(out, key)
        }
        return out
    }

    private fun patchKeyLanesBinary(classBytes: ByteArray, key: ByteArray): ByteArray {
        val out = classBytes.copyOf()
        for (lane in 0 until 4) {
            val sentinel = 0x4A535230 + lane
            val needle = byteArrayOf(
                ((sentinel ushr 24) and 0xFF).toByte(),
                ((sentinel ushr 16) and 0xFF).toByte(),
                ((sentinel ushr 8) and 0xFF).toByte(),
                (sentinel and 0xFF).toByte(),
            )
            val replacement = key.copyOfRange(lane * 4, lane * 4 + 4)
            val index = indexOfBytes(out, needle)
            if (index >= 0) {
                replacement.copyInto(out, index)
            }
        }
        return out
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (start in 0..haystack.size - needle.size) {
            for (offset in needle.indices) {
                if (haystack[start + offset] != needle[offset]) continue@outer
            }
            return start
        }
        return -1
    }
}
