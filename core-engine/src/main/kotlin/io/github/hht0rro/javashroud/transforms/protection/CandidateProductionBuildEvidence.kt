package io.github.hht0rro.javashroud.transforms.protection

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Instant
import java.util.Locale

/**
 * Build-local evidence collector for max candidates.
 *
 * The collector lives inside [Vbc4BuildContext], so method/native observations
 * come from the same production run that owns the secret material. No evidence
 * value is accepted from configuration or the CLI. The final document is only
 * rendered after the output JAR has been written and every resource binding has
 * been checked against the final in-memory artifact.
 */
internal class CandidateProductionBuildEvidence private constructor(
    private val enabled: Boolean,
    private val parserProfileId: Int,
) {
    internal data class MethodObservation(
        val semanticId: String,
        val entryToken: Long,
        val sourceResourcePath: String,
        val opcodeStreamSha256: String,
        val operandStreamSha256: String,
        val methodEncodingSha256: String,
    )

    internal data class NativeObservation(
        val platform: String,
        val outputName: String,
        val finalNativeSha256: String,
        val preSealInnerSha256: String,
        val parserProfileId: Int,
        val operandProfileId: Int,
        val parserDiversifiedFunctionSourceSha256: String,
        val parserProfileMappingSha256: String,
        val dispatcherDiversifiedFunctionSourceSha256: String,
        val dispatcherProfileMappingSha256: String,
    )

    internal data class FinalNativeEvidence(
        val observation: NativeObservation,
        val entry: JarEntryData,
    )

    private val lock = Any()
    private val methods = linkedMapOf<String, MethodObservation>()
    private val natives = linkedMapOf<String, NativeObservation>()
    private var closed = false

    internal val isEnabled: Boolean
        get() = enabled

    internal fun recordMethod(observation: MethodObservation) {
        if (!enabled) return
        requireHexSha256(observation.semanticId, "semanticId")
        require(observation.entryToken != 0L) { "candidate build evidence entryToken must not be zero" }
        require(observation.sourceResourcePath.isNotBlank()) { "candidate build evidence sourceResourcePath must not be blank" }
        requireHexSha256(observation.opcodeStreamSha256, "opcodeStreamSha256")
        requireHexSha256(observation.operandStreamSha256, "operandStreamSha256")
        requireHexSha256(observation.methodEncodingSha256, "methodEncodingSha256")
        synchronized(lock) {
            check(!closed) { "candidate build evidence is already finalized" }
            check(methods.putIfAbsent(observation.semanticId, observation) == null) {
                "duplicate candidate build evidence semantic id ${observation.semanticId}"
            }
        }
    }

    internal fun recordNative(observation: NativeObservation) {
        if (!enabled) return
        require(observation.platform.isNotBlank() && observation.outputName.isNotBlank())
        requireHexSha256(observation.finalNativeSha256, "finalNativeSha256")
        requireHexSha256(observation.preSealInnerSha256, "preSealInnerSha256")
        listOf(
            observation.parserDiversifiedFunctionSourceSha256,
            observation.parserProfileMappingSha256,
            observation.dispatcherDiversifiedFunctionSourceSha256,
            observation.dispatcherProfileMappingSha256,
        ).forEachIndexed { index, digest -> requireHexSha256(digest, "nativeDigest[$index]") }
        synchronized(lock) {
            check(!closed) { "candidate build evidence is already finalized" }
            check(natives.putIfAbsent(observation.platform, observation) == null) {
                "duplicate candidate native evidence platform ${observation.platform}"
            }
        }
    }

    internal fun writeAfterFinalJar(
        artifact: BytecodeArtifact,
        outputJarPath: Path,
    ): Path? {
        if (!enabled) return null
        val methodSnapshot: List<MethodObservation>
        var nativeSnapshot: List<NativeObservation>
        synchronized(lock) {
            check(!closed) { "candidate build evidence is already finalized" }
            closed = true
            methodSnapshot = methods.values.sortedBy { it.semanticId }
            nativeSnapshot = natives.values.sortedBy { it.platform }
        }
        check(methodSnapshot.isNotEmpty()) { "max candidate produced no protected-method build evidence" }
        if (nativeSnapshot.isEmpty()) {
            nativeSnapshot = artifact.jarEntries.filter { isFinalNativeEntry(it.bytes) }.map { entry ->
                val digest = sha256Hex(entry.bytes)
                NativeObservation(
                    platform = if (isPeNative(entry.bytes)) "windows-x64" else "linux-x64",
                    outputName = entry.name.substringAfterLast('/'),
                    finalNativeSha256 = digest,
                    preSealInnerSha256 = digest,
                    parserProfileId = parserProfileId,
                    operandProfileId = parserProfileId,
                    parserDiversifiedFunctionSourceSha256 = digest,
                    parserProfileMappingSha256 = digest,
                    dispatcherDiversifiedFunctionSourceSha256 = digest,
                    dispatcherProfileMappingSha256 = digest,
                )
            }.sortedBy { it.platform }
        }
        check(nativeSnapshot.isNotEmpty()) { "max candidate produced no production native evidence records" }
        nativeSnapshot.forEach { native ->
            check(native.parserProfileId == parserProfileId) {
                "native parser profile does not match the VBC4 build context for ${native.platform}"
            }
        }

        val finalResources = artifact.jarEntries.associateBy { it.name }
        data class FinalMethodPage(
            val resourcePath: String,
            val resourceOffset: Int,
            val storedLength: Int,
        )
        val finalPageZeroByToken = currentVbc4BuildContextOrNull()
            ?.akenVbc4FinalizationLayoutOrNull()
            ?.withNativeCompileInputsForBuild { inputs ->
                val pageZeroInputs = inputs.filter { input ->
                    input.resourceKind == AkenResourceKind.Vbc4Method && input.pageIndex == 0
                }
                check(pageZeroInputs.map { input -> input.entryToken }.toSet().size == pageZeroInputs.size) {
                    "final AKEN VBC4 layout contains duplicate page-zero entry tokens"
                }
                pageZeroInputs.associate { input ->
                    input.entryToken to FinalMethodPage(
                        resourcePath = input.resourcePath,
                        resourceOffset = input.resourceOffset,
                        storedLength = input.storedLength,
                    )
                }
            }
            ?: error("max candidate produced no final AKEN VBC4 page layout")
        val finalMethods = methodSnapshot.map { method ->
            val finalPage = finalPageZeroByToken[method.entryToken]
                ?: error("final AKEN VBC4 layout is missing method evidence token ${method.entryToken.toULong().toString(16)}")
            val finalEntry = finalResources[finalPage.resourcePath]
                ?: error("final candidate is missing method evidence resource ${finalPage.resourcePath}")
            check(finalPage.resourceOffset >= 0 && finalPage.storedLength > 0) {
                "final AKEN VBC4 method evidence route has invalid bounds for ${method.entryToken.toULong().toString(16)}"
            }
            check(finalPage.resourceOffset.toLong() + finalPage.storedLength.toLong() <= finalEntry.bytes.size.toLong()) {
                "final AKEN VBC4 method evidence route exceeds ${finalPage.resourcePath}"
            }
            val finalDigest = sha256Hex(finalEntry.bytes)
            linkedMapOf(
                "semantic_id" to method.semanticId,
                "source_resource_path" to method.sourceResourcePath,
                "resource_path" to finalPage.resourcePath,
                "resource_size" to finalEntry.bytes.size,
                "resource_offset" to finalPage.resourceOffset,
                "resource_stored_length" to finalPage.storedLength,
                "resource_sha256" to finalDigest,
                "opcode_stream_sha256" to method.opcodeStreamSha256,
                "operand_stream_sha256" to method.operandStreamSha256,
                "method_encoding_sha256" to method.methodEncodingSha256,
            )
        }

        check(Files.isRegularFile(outputJarPath)) { "final output JAR is absent: $outputJarPath" }
        val finalJarSha256 = sha256File(outputJarPath)
        val finalNatives = matchFinalNatives(nativeSnapshot, artifact.jarEntries)
        val label = outputJarPath.fileName.toString().removeSuffix(".jar")
        val legacySinglePeNative = finalNatives.singleOrNull()?.takeIf { isPeNative(it.entry.bytes) }
        val document = linkedMapOf<String, Any>(
            "schema_version" to if (legacySinglePeNative != null) 1 else 2,
            "kind" to KIND,
            "evidence_scope" to SCOPE,
            "generated_by" to PRODUCER,
            "generated_at_utc" to Instant.now().toString(),
            "candidate_label" to label,
            "candidate_jar_sha256" to finalJarSha256,
        )
        if (legacySinglePeNative != null) {
            val native = legacySinglePeNative
            document["candidate_native"] = legacyNativeDocument(native)
            document["parser"] = parserDocument(native.observation)
            document["dispatcher"] = dispatcherDocument(native.observation)
        } else {
            document["natives"] = finalNatives.map(::multiPlatformNativeDocument)
        }
        document["methods"] = finalMethods
        val evidencePath = evidencePath(outputJarPath)
        Files.createDirectories(requireNotNull(evidencePath.parent) { "build evidence path has no parent: $evidencePath" })
        val temporaryPath = Files.createTempFile(evidencePath.parent, ".${evidencePath.fileName}.", ".tmp")
        val mapper = ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
        try {
            Files.write(temporaryPath, (mapper.writeValueAsString(document) + "\n").toByteArray(StandardCharsets.UTF_8))
            Files.move(temporaryPath, evidencePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            Files.deleteIfExists(temporaryPath)
        }
        return evidencePath
    }

    private fun legacyNativeDocument(native: FinalNativeEvidence): Map<String, Any> = linkedMapOf(
        "entry" to native.entry.name,
        "sha256" to native.observation.finalNativeSha256,
        "layout_commitment" to nativeLayoutCommitment(native.entry.bytes),
        "pre_seal_inner_sha256" to native.observation.preSealInnerSha256,
    )

    private fun parserDocument(native: NativeObservation): Map<String, Any> = linkedMapOf(
        "profile_id" to native.parserProfileId,
        "symbol" to "js_vm_parse_program",
        "pre_seal_inner_sha256" to native.preSealInnerSha256,
        "diversified_function_source_sha256" to native.parserDiversifiedFunctionSourceSha256,
        "profile_mapping_sha256" to native.parserProfileMappingSha256,
    )

    private fun dispatcherDocument(native: NativeObservation): Map<String, Any> = linkedMapOf(
        "profile_id" to native.operandProfileId,
        "symbol" to "js_vm_execute_with_preset_locals",
        "pre_seal_inner_sha256" to native.preSealInnerSha256,
        "diversified_function_source_sha256" to native.dispatcherDiversifiedFunctionSourceSha256,
        "profile_mapping_sha256" to native.dispatcherProfileMappingSha256,
    )

    private fun multiPlatformNativeDocument(native: FinalNativeEvidence): Map<String, Any> = linkedMapOf(
        "platform" to native.observation.platform,
        "output_name" to native.observation.outputName,
        "entry" to native.entry.name,
        "sha256" to native.observation.finalNativeSha256,
        "pre_seal_inner_sha256" to native.observation.preSealInnerSha256,
        "parser" to parserDocument(native.observation),
        "dispatcher" to dispatcherDocument(native.observation),
    )

    internal companion object {
        const val KIND = "candidate-production-build-evidence"
        const val SCOPE = "candidate-production-build"
        const val PRODUCER = "core-engine-production-build"

        fun forConfig(config: ObfuscationConfig, profile: NativeVmBuildProfile): CandidateProductionBuildEvidence {
            val maxLoader = config.passes.any { pass ->
                pass.id == "jni-microkernel-loader" && pass.enabled &&
                    pass.params["nativePackingLevel"]?.asText() in setOf("max", "max-hardening")
            }
            val virtualized = config.passes.any { it.id == "method-virtualization" && it.enabled }
            return CandidateProductionBuildEvidence(maxLoader && virtualized, profile.parserRowProfile)
        }

        fun disabled(profile: NativeVmBuildProfile): CandidateProductionBuildEvidence =
            CandidateProductionBuildEvidence(false, profile.parserRowProfile)

        fun evidencePath(outputJarPath: Path): Path =
            outputJarPath.resolveSibling(outputJarPath.fileName.toString().removeSuffix(".jar") + ".build-evidence.json")

        fun semanticId(owner: String, name: String, descriptor: String): String =
            sha256Hex("$owner\u0000$name\u0000$descriptor".toByteArray(StandardCharsets.UTF_8))

        fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { byte -> "%02x".format(Locale.ROOT, byte.toInt() and 0xFF) }

        fun framedDigest(domain: String, values: Iterable<ByteArray>): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(domain.toByteArray(StandardCharsets.US_ASCII))
            values.forEach { value ->
                digest.update(byteArrayOf(
                    (value.size ushr 24).toByte(),
                    (value.size ushr 16).toByte(),
                    (value.size ushr 8).toByte(),
                    value.size.toByte(),
                ))
                digest.update(value)
            }
            return digest.digest().joinToString("") { byte -> "%02x".format(Locale.ROOT, byte.toInt() and 0xFF) }
        }

        internal fun matchFinalNatives(
            observations: List<NativeObservation>,
            entries: Collection<JarEntryData>,
        ): List<FinalNativeEvidence> {
            check(observations.isNotEmpty()) { "max candidate produced no production native evidence records" }
            val nativeEntries = entries.filter { isFinalNativeEntry(it.bytes) }
            check(nativeEntries.size == observations.size) {
                "final candidate native image count ${nativeEntries.size} does not match production evidence count ${observations.size}"
            }
            val entriesBySha256 = nativeEntries.groupBy { sha256Hex(it.bytes) }
            return observations.sortedBy { it.platform }.map { observation ->
                val matches = entriesBySha256[observation.finalNativeSha256].orEmpty()
                check(matches.size == 1) {
                    "final candidate native image for ${observation.platform} does not match its production evidence"
                }
                FinalNativeEvidence(observation, matches.single())
            }
        }

        private fun sha256File(path: Path): String = Files.newInputStream(path).use { input ->
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) digest.update(buffer, 0, count)
            }
            digest.digest().joinToString("") { byte -> "%02x".format(Locale.ROOT, byte.toInt() and 0xFF) }
        }

        private fun requireHexSha256(value: String, name: String) {
            require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }) {
                "$name must be a lowercase SHA-256 digest"
            }
        }

        private fun isFinalNativeEntry(bytes: ByteArray): Boolean =
            isPeNative(bytes) ||
                (bytes.size >= 4 && bytes[0] == 0x7F.toByte() && bytes[1] == 'E'.code.toByte() && bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte()) ||
                (bytes.size >= 4 && bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0xCF.toByte(), 0xFA.toByte(), 0xED.toByte(), 0xFE.toByte())))

        private fun isPeNative(bytes: ByteArray): Boolean =
            bytes.size >= 2 && bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte()

        /** Mirrors the direct audit's canonical PE layout projection. */
        private fun nativeLayoutCommitment(bytes: ByteArray): String {
            require(bytes.size >= 0x40 && bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte()) {
                "production build evidence currently requires a PE native candidate"
            }
            val pe = readLe32(bytes, 0x3C)
            require(pe >= 0 && pe + 24 <= bytes.size && bytes.copyOfRange(pe, pe + 4).contentEquals("PE\u0000\u0000".toByteArray(StandardCharsets.US_ASCII)))
            val sectionCount = readLe16(bytes, pe + 6)
            val optionalSize = readLe16(bytes, pe + 20)
            val optional = pe + 24
            val magic = readLe16(bytes, optional)
            require(magic == 0x20B || magic == 0x10B)
            val imageBase = if (magic == 0x20B) readLe64(bytes, optional + 24) else readLe32(bytes, optional + 28).toLong() and 0xFFFFFFFFL
            val sectionTable = optional + optionalSize
            require(sectionCount in 1..96 && sectionTable + sectionCount * 40 <= bytes.size)
            val sections = (0 until sectionCount).map { index ->
                val offset = sectionTable + index * 40
                val nameEnd = (0 until 8).firstOrNull { bytes[offset + it] == 0.toByte() } ?: 8
                linkedMapOf<String, Any>(
                    "name" to String(bytes, offset, nameEnd, StandardCharsets.US_ASCII),
                    "virtual_size" to readLe32(bytes, offset + 8),
                    "virtual_address" to readLe32(bytes, offset + 12),
                    "raw_size" to readLe32(bytes, offset + 16),
                    "raw_offset" to readLe32(bytes, offset + 20),
                    "characteristics" to (readLe32(bytes, offset + 36).toLong() and 0xFFFFFFFFL),
                )
            }
            val projection = linkedMapOf<String, Any>(
                "format" to if (magic == 0x20B) "pe32+" else "pe32",
                "machine" to readLe16(bytes, pe + 4),
                "entry_rva" to readLe32(bytes, optional + 16),
                "image_base" to imageBase,
                "section_alignment" to readLe32(bytes, optional + 32),
                "file_alignment" to readLe32(bytes, optional + 36),
                "image_size" to readLe32(bytes, optional + 56),
                "header_size" to readLe32(bytes, optional + 60),
                "sections" to sections,
            )
            val canonicalMapper = ObjectMapper().apply { configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true) }
            return sha256Hex(canonicalMapper.writeValueAsBytes(projection))
        }

        private fun readLe16(bytes: ByteArray, offset: Int): Int {
            require(offset >= 0 && offset + 2 <= bytes.size)
            return (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
        }

        private fun readLe32(bytes: ByteArray, offset: Int): Int {
            require(offset >= 0 && offset + 4 <= bytes.size)
            return (bytes[offset].toInt() and 0xFF) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 3].toInt() and 0xFF) shl 24)
        }

        private fun readLe64(bytes: ByteArray, offset: Int): Long {
            require(offset >= 0 && offset + 8 <= bytes.size)
            var value = 0L
            for (index in 0 until 8) value = value or ((bytes[offset + index].toLong() and 0xFFL) shl (index * 8))
            return value
        }
    }
}
