package io.github.hht0rro.javashroud.transforms.protection

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object NativeKernelPacker {
    private val nativeNamePattern = Regex("js_kernel_(.+)\\.(dll|so|dylib)")
    private val bootstrapIndexMagic = byteArrayOf(0x4A, 0x53, 0x42, 0x49) // JSBI
    private const val bootstrapIndexVersion = 1
    private const val bootstrapIndexHeaderSize = 9
    private const val bootstrapIndexMacLength = 32

    data class PackedResource(val path: String, val bytes: ByteArray)
    data class PackResult(val indexPath: String, val indexBytes: ByteArray, val resources: List<PackedResource>)

    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size >= 2) { "usage: NativeKernelPacker <input-dir> <output-dir> [seed]" }
        val seed = args.getOrNull(2)?.toLongOrNull() ?: 0x4A53524CL
        pack(Path.of(args[0]), Path.of(args[1]), seed)
    }

    fun pack(inputDir: Path, outputDir: Path, seed: Long = 0x4A53524CL): PackResult {
        if (Files.exists(outputDir)) {
            Files.walk(outputDir).use { stream ->
                stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
        Files.createDirectories(outputDir)
        val nativeFiles = if (Files.isDirectory(inputDir)) {
            Files.list(inputDir).use { stream ->
                stream.filter { path -> Files.isRegularFile(path) && nativeNamePattern.matches(path.fileName.toString()) }
                    .sorted(Comparator.comparing { path -> path.fileName.toString() })
                    .toList()
            }
        } else {
            emptyList()
        }
        val resources = mutableListOf<PackedResource>()
        val indexLines = mutableListOf<String>()
        for ((index, path) in nativeFiles.withIndex()) {
            val match = checkNotNull(nativeNamePattern.matchEntire(path.fileName.toString()))
            val platform = match.groupValues[1]
            val suffix = ".${match.groupValues[2]}"
            val rawBytes = Files.readAllBytes(path)
            val resourcePath = neutralResourcePath(seed, platform, index, ".bin")
            Files.createDirectories(outputDir.resolve(resourcePath).parent)
            Files.write(outputDir.resolve(resourcePath), rawBytes)
            resources += PackedResource(resourcePath, rawBytes)
            indexLines += listOf(platform, resourcePath, suffix).joinToString("|")
        }
        val indexPath = "META-INF/.r/0.dat"
        val indexPlain = indexLines.joinToString(separator = "\n", postfix = if (indexLines.isEmpty()) "" else "\n")
            .toByteArray(Charsets.UTF_8)
        val indexBytes = encodeBootstrapNativeIndex(indexPlain)
        Files.createDirectories(outputDir.resolve(indexPath).parent)
        Files.write(outputDir.resolve(indexPath), indexBytes)
        return PackResult(indexPath = indexPath, indexBytes = indexBytes, resources = resources)
    }

    private fun neutralResourcePath(seed: Long, value: String, index: Int, suffix: String): String {
        val digest = digest(seed, "path", value, index)
        val nbspSegment = "${digest.take(1)}\u00A0${digest.drop(1).take(1)}"
        return "META-INF/$nbspSegment/${digest.drop(2).take(14)}/${digest.drop(16).take(24)}$suffix"
    }

    private fun digest(seed: Long, kind: String, value: String, index: Int): String =
        MessageDigest.getInstance("SHA-256")
            .digest("$seed|$kind|$index|$value".toByteArray(Charsets.UTF_8))
            .toHexLower()

    private fun encodeBootstrapNativeIndex(plain: ByteArray): ByteArray {
        val out = ByteArray(bootstrapIndexHeaderSize + plain.size + bootstrapIndexMacLength + 1)
        System.arraycopy(bootstrapIndexMagic, 0, out, 0, bootstrapIndexMagic.size)
        out[4] = bootstrapIndexVersion.toByte()
        writeLe32(out, 5, plain.size)
        System.arraycopy(plain, 0, out, bootstrapIndexHeaderSize, plain.size)
        val tag = hmacBootstrapNativeIndex(out, 0, bootstrapIndexHeaderSize + plain.size)
        System.arraycopy(tag, 0, out, bootstrapIndexHeaderSize + plain.size, tag.size)
        out[out.lastIndex] = bootstrapIndexMacLength.toByte()
        return out
    }

    private fun hmacBootstrapNativeIndex(bytes: ByteArray, offset: Int, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val key = requireVbc4BuildContext().copyRuntimeResourceKey()
        return try {
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            mac.update("jsbi-auth".toByteArray(Charsets.US_ASCII))
            mac.update(bytes, offset, length)
            mac.doFinal()
        } finally {
            Arrays.fill(key, 0)
        }
    }

    private fun writeLe32(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value and 0xFF).toByte()
        out[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        out[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        out[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }


}

