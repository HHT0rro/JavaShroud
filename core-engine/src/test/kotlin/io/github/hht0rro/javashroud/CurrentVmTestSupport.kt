package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.transforms.protection.CandidateProductionBuildEvidence
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarFile
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode

internal fun hasRecordedCurrentVmMethod(jar: Path, owner: String, name: String, descriptor: String): Boolean {
    val evidencePath = CandidateProductionBuildEvidence.evidencePath(jar)
    if (!Files.isRegularFile(evidencePath)) return false
    val evidence = ObjectMapper().readTree(Files.readAllBytes(evidencePath))
    val jarDigest = CandidateProductionBuildEvidence.sha256Hex(Files.readAllBytes(jar))
    if (evidence.path("candidate_jar_sha256").asText() != jarDigest) return false
    val semanticId = CandidateProductionBuildEvidence.semanticId(owner, name, descriptor)
    val method = evidence.path("methods").firstOrNull { it.path("semantic_id").asText() == semanticId } ?: return false
    return JarFile(jar.toFile()).use { archive ->
        val resource = archive.getJarEntry(method.path("resource_path").asText())
            // Page routes can refer into a bundle whose sealed name belongs to
            // the completed build context. Bind that container by its recorded
            // size and digest after verifying the whole JAR identity above.
            ?: archive.entries().asSequence().filter { entry ->
                !entry.isDirectory && entry.size == method.path("resource_size").asLong(-1)
            }.singleOrNull { entry ->
                archive.getInputStream(entry).use {
                    CandidateProductionBuildEvidence.sha256Hex(it.readBytes()) == method.path("resource_sha256").asText()
                }
            }
            ?: return@use false
        val resourceDigest = archive.getInputStream(resource).use { CandidateProductionBuildEvidence.sha256Hex(it.readBytes()) }
        if (method.path("resource_sha256").asText() != resourceDigest) return@use false
        val classEntry = archive.getJarEntry("$owner.class") ?: return@use false
        val node = ClassNode()
        archive.getInputStream(classEntry).use { ClassReader(it.readBytes()).accept(node, ClassReader.SKIP_FRAMES) }
        node.methods.any { candidate ->
            candidate.instructions.toArray().any { call ->
                when (call) {
                    is MethodInsnNode -> call.opcode == Opcodes.INVOKESTATIC &&
                        call.desc == "(Ljava/lang/String;[BI[B[Ljava/lang/Object;)Ljava/lang/Object;"
                    is InvokeDynamicInsnNode -> call.desc == "(Ljava/lang/String;[BI[B[Ljava/lang/Object;)Ljava/lang/Object;" &&
                        call.bsm.owner != "java/lang/invoke/LambdaMetafactory"
                    else -> false
                }
            }
        }
    }
}
