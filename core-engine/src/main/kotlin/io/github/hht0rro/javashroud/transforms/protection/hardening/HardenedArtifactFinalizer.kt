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

internal object HardenedArtifactFinalizer {
    fun finalizeForWrite(artifact: BytecodeArtifact, config: ObfuscationConfig): BytecodeArtifact {
        val draft = captureRenameDraft(artifact)
        currentVbc4BuildContextOrNull()?.publishSignedDebugMapDraft(draft)
        if (config.protectionProfile == HardenedProtectionProfile.MINIMAL) return artifact
        return wrapIndyTargets(artifact)
    }

    /** Wrap business invokedynamic targets after natives are final and before catalog attach. */
    fun wrapIndyTargets(artifact: BytecodeArtifact): BytecodeArtifact {
        val digest = artifactDigest(artifact)
        return IndyTargetRewriter.wrapBusinessHandles(injectIndyBootstrap(artifact), digest)
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


    private fun artifactDigest(artifact: BytecodeArtifact): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(ProtectionFormat.CURRENT.toByteArray())
        artifact.classArtifacts.sortedBy { it.entryName }.forEach { classArtifact ->
            digest.update(classArtifact.entryName.toByteArray())
            digest.update(classArtifact.bytes)
        }
        return digest.digest()
    }

    private fun injectIndyBootstrap(artifact: BytecodeArtifact): BytecodeArtifact {
        val internalName = IndyTargetRewriter.BOOTSTRAP_OWNER
        val entryName = internalName + ".class"
        val existing = artifact.classArtifacts.firstOrNull { it.summary.internalName == internalName }
        if (existing != null) return artifact
        val resource = "/" + entryName
        val raw = HardenedArtifactFinalizer::class.java.getResourceAsStream(resource)?.readBytes()
            ?: return artifact
        val summary = analyzeClassBytes(raw)
        val classArtifact = ClassArtifact(entryName, summary, raw)
        val classArtifacts = artifact.classArtifacts + classArtifact
        val jarEntries = artifact.jarEntries + JarEntryData(entryName, raw)
        return artifact.copy(
            jarEntries = jarEntries,
            classArtifacts = classArtifacts,
            classArtifactIndex = classArtifactIndex(classArtifacts),
        )
    }
}
