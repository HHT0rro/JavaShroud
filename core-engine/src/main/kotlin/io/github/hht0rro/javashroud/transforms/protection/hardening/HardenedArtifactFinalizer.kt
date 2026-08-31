package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.currentQpBuildContextOrNull
import io.github.hht0rro.javashroud.transforms.rename.FIELD_RENAME_BINDINGS_RESOURCE
import io.github.hht0rro.javashroud.transforms.rename.METHOD_RENAME_BINDINGS_RESOURCE
import java.security.MessageDigest
import java.util.Arrays

internal object HardenedArtifactFinalizer {
    fun finalizeForWrite(artifact: BytecodeArtifact, config: ObfuscationConfig): BytecodeArtifact {
        val draft = captureRenameDraft(artifact)
        currentQpBuildContextOrNull()?.publishSignedDebugMapDraft(draft)
        if (config.protectionProfile == HardenedProtectionProfile.MINIMAL) return artifact
        return wrapIndyTargets(artifact)
    }

    /** Wrap business invokedynamic targets after natives are final and before catalog attach. */
    fun wrapIndyTargets(artifact: BytecodeArtifact): BytecodeArtifact {
        val prepared = injectIndyBootstrap(artifact)
        val context = currentQpBuildContextOrNull()
        val digest = context?.qpFinalizationLayoutOrNull()?.copyArtifactCommitmentForBuild()
            ?: context?.qpBuildPlanOrNull()?.artifactCanonicalCommitment
            ?: context?.jarLayoutDigest?.copyOf()
            ?: artifactDigest(prepared)
        return try {
            QpTargetRewriter.wrapBusinessHandles(prepared, digest)
        } finally {
            Arrays.fill(digest, 0)
        }
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
            transformVersion = ProtectionFormat.CURRENT_LABEL,
            buildId = currentQpBuildContextOrNull()?.nativeSeed?.toString(16) ?: "build",
        )
    }


    private fun artifactDigest(artifact: BytecodeArtifact): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(ProtectionFormat.CURRENT_LABEL.toByteArray())
        artifact.classArtifacts.sortedBy { it.entryName }.forEach { classArtifact ->
            digest.update(classArtifact.entryName.toByteArray())
            digest.update(classArtifact.bytes)
        }
        return digest.digest()
    }

    private fun injectIndyBootstrap(artifact: BytecodeArtifact): BytecodeArtifact {
        val internalName = QpTargetRewriter.BOOTSTRAP_OWNER
        val entryName = internalName + ".class"
        // The sealing pass may already have relocated QpBootstrap. Detect the
        // owner by its authenticated bootstrap signature instead of appending
        // a second canonical class that still points at the old QpBridge name.
        if (QpTargetRewriter.bootstrapTargetOrNull(artifact) != null) return artifact
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
