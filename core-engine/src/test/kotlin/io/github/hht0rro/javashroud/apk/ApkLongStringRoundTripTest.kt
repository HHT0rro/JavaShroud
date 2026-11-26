package io.github.hht0rro.javashroud.apk

import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.Type

class ApkLongStringRoundTripTest {
    @Test
    fun asciiBelowThePreviousSplitThreshold(@TempDir work: Path) {
        assertStringRoundTrip(work, "A".repeat(32_766))
    }

    @Test
    fun asciiAtThePreviousSplitThreshold(@TempDir work: Path) {
        assertStringRoundTrip(work, "A".repeat(32_767))
    }

    @Test
    fun asciiAboveThePreviousSplitThreshold(@TempDir work: Path) {
        assertStringRoundTrip(work, "A".repeat(32_768))
    }

    @Test
    fun asciiAtTheClassfileModifiedUtf8Limit(@TempDir work: Path) {
        assertStringRoundTrip(work, "A".repeat(65_535))
    }

    @Test
    fun asciiAboveTheClassfileModifiedUtf8Limit(@TempDir work: Path) {
        assertStringRoundTrip(work, "A".repeat(65_536))
    }

    @Test
    fun longConstantPreservesAnAdjacentLiveRegister(@TempDir work: Path) {
        val value = "A".repeat(65_536)
        val suffix = ":adjacent-still-live"
        assertRoundTrip(work, value + suffix, """
            .registers 2
            const-string v1, ${smaliString(suffix)}
            const-string v0, ${smaliString(value)}
            invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
            move-result-object v0
            return-object v0
        """.trimIndent())
    }

    @Test
    fun longConstantPreservesAnAdjacentLiveInt(@TempDir work: Path) {
        val value = "A".repeat(65_536)
        assertRoundTrip(work, value + "42", """
            .registers 2
            const/16 v1, 0x2a
            const-string v0, ${smaliString(value)}
            invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
            move-result-object v1
            invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
            move-result-object v0
            return-object v0
        """.trimIndent())
    }

    @Test
    fun longConstantPreservesAnAdjacentLiveWideValue(@TempDir work: Path) {
        val value = "A".repeat(65_536)
        assertRoundTrip(work, value + "42", """
            .registers 3
            const-wide/16 v1, 0x2a
            const-string v0, ${smaliString(value)}
            invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;
            move-result-object v1
            invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
            move-result-object v0
            return-object v0
        """.trimIndent())
    }

    @Test
    fun incomingArgumentsFollowShiftedRegisters(@TempDir work: Path) {
        val value = "A".repeat(65_536)
        val suffix = ":incoming-argument"
        assertRoundTrip(
            work, value + suffix + "42", """
                .registers 3
                const-string v0, ${smaliString(value)}
                invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
                move-result-object v0
                invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
                move-result-object v1
                invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
                move-result-object v0
                return-object v0
            """.trimIndent(),
            parameterTypes = arrayOf(String::class.java, java.lang.Integer.TYPE),
            arguments = arrayOf(suffix, 42),
        )
    }

    @Test
    fun incomingWideArgumentFollowsShiftedRegisters(@TempDir work: Path) {
        val value = "A".repeat(65_536)
        assertRoundTrip(
            work, value + "42", """
                .registers 3
                const-string v0, ${smaliString(value)}
                invoke-static {p0, p1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;
                move-result-object v1
                invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
                move-result-object v0
                return-object v0
            """.trimIndent(),
            parameterTypes = arrayOf(java.lang.Long.TYPE),
            arguments = arrayOf(42L),
        )
    }

    @Test
    fun mixedUnicodeAtTheClassfileModifiedUtf8Limit(@TempDir work: Path) {
        // Each repeated group occupies 11 modified UTF-8 bytes, including six for the surrogate pair.
        val value = "\u0000\u0800\uD83D\uDE00".repeat(5_957) + "\u0800\u0800\u0000"
        assertStringRoundTrip(work, value)
    }

    @Test
    fun mixedUnicodeAboveTheClassfileModifiedUtf8Limit(@TempDir work: Path) {
        val value = "\u0000\u0800\uD83D\uDE00".repeat(5_957) + "\u0800\u0800\u0000A"
        assertStringRoundTrip(work, value)
    }

    @Test
    fun nulCharactersRequireTwoModifiedUtf8Bytes(@TempDir work: Path) {
        assertStringRoundTrip(work, "\u0000".repeat(32_768))
    }

    @Test
    fun threeByteCharactersSpanTheClassfileConstantLimit(@TempDir work: Path) {
        assertStringRoundTrip(work, "\u0800".repeat(32_768))
    }

    @Test
    fun supplementaryCharactersRequireSixModifiedUtf8Bytes(@TempDir work: Path) {
        assertStringRoundTrip(work, "\uD83D\uDE00".repeat(16_384))
    }

    @Test
    fun shortConstantKeepsTheExceptionLiveDestinationType(@TempDir work: Path) {
        assertExceptionLiveDestination(work, "short")
    }

    @Test
    fun oversizedConstantKeepsTheExceptionLiveDestinationType(@TempDir work: Path) {
        assertExceptionLiveDestination(work, "A".repeat(65_536))
    }

    private fun assertExceptionLiveDestination(work: Path, value: String) {
        val body = """
            .registers 3
            const-string v0, "retained-before-assignment"
            :try_start
            if-eqz p0, :assign
            new-instance v1, Ljava/lang/IllegalArgumentException;
            invoke-direct {v1}, Ljava/lang/IllegalArgumentException;-><init>()V
            throw v1
            :assign
            const-string v0, ${smaliString(value)}
            :try_end
            return-object v0
            .catch Ljava/lang/IllegalArgumentException; {:try_start .. :try_end} :handler
            :handler
            move-exception v1
            return-object v0
        """.trimIndent()
        for (throwBeforeAssignment in listOf(false, true)) {
            assertRoundTrip(
                Files.createDirectory(work.resolve("throw-$throwBeforeAssignment")),
                if (throwBeforeAssignment) "retained-before-assignment" else value,
                body,
                parameterTypes = arrayOf(java.lang.Boolean.TYPE),
                arguments = arrayOf(throwBeforeAssignment),
                literalIdentity = true,
            )
        }
    }

    private fun assertStringRoundTrip(work: Path, value: String) {
        assertRoundTrip(
            work, value, """
                .registers 1
                const-string v0, ${smaliString(value)}
                return-object v0
            """.trimIndent(),
            literalIdentity = true,
        )
    }

    private fun assertRoundTrip(
        work: Path,
        expected: String,
        body: String,
        parameterTypes: Array<Class<*>> = emptyArray(),
        arguments: Array<Any> = emptyArray(),
        literalIdentity: Boolean = false,
    ) {
        Assumptions.assumeTrue(
            System.getenv(ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV) != "skip",
            "JAVASHROUD_APK_REAL_TOOLS=skip",
        )
        val toolchain = ApkToolchainProvisioner.ensure(dex2jarDirOverride = "", d8JarOverride = "")
        val argumentTypes = parameterTypes.map { Type.getType(it) }.toTypedArray()
        val descriptor = Type.getMethodDescriptor(Type.getType(String::class.java), *argumentTypes)
        val source = Files.writeString(work.resolve("LongString.smali"), """
            .class public Lfixture/LongString;
            .super Ljava/lang/Object;

            .method public static value$descriptor
                $body
            .end method
        """.trimIndent())
        val inputDex = work.resolve("classes.dex")
        val assembler = listOf(
            toolchain.javaExecutable.toString(), "-Xmx256m", "-cp",
            ApkDex2JarRunner.wildcardClasspath(toolchain.dex2jarDirectory),
            "com.googlecode.d2j.smali.SmaliCmd", "--output", inputDex.toString(), source.toString(),
        )
        ApkProcessSupport.requireSuccess(
            "assemble long string fixture", assembler, ApkProcessSupport.runProcess(assembler, 60_000),
        )
        val inputBytes = Files.readAllBytes(inputDex)
        ApkValidation.validateDexHeader("classes.dex", inputBytes)
        val converted = ApkDex2JarRunner().convert(
            toolchain, ApkInputUnpacker.ApkDexInput("classes.dex", 1, inputBytes), work,
        ) {}
        assertTrue("fixture/LongString.class" in converted.classNames)
        assertReturnedString(converted.jarPath, expected, "DEX to JVM", parameterTypes, arguments, literalIdentity)

        val roundTripDex = ApkD8Runner().compile(
            toolchain, converted.jarPath, work.resolve("d8-round-trip"), minApi = 26, androidJarPath = "",
        ) {}.single()
        ApkValidation.validateDexHeader(roundTripDex.first, roundTripDex.second)
        val roundTripClasses = ApkDex2JarRunner().convert(
            toolchain, ApkInputUnpacker.ApkDexInput(roundTripDex.first, 1, roundTripDex.second), work,
        ) {}
        assertReturnedString(roundTripClasses.jarPath, expected, "DEX to JVM to D8 to JVM", parameterTypes, arguments, literalIdentity)
    }

    private fun assertReturnedString(
        jar: Path,
        expected: String,
        stage: String,
        parameterTypes: Array<Class<*>>,
        arguments: Array<Any>,
        literalIdentity: Boolean,
    ) {
        URLClassLoader(arrayOf(jar.toUri().toURL()), null).use { loader ->
            val actual = loader.loadClass("fixture.LongString").getMethod("value", *parameterTypes).invoke(null, *arguments)
            assertEquals(expected, actual, "$stage must preserve every UTF-16 code unit")
            if (literalIdentity) assertSame(expected.intern(), actual, "$stage must preserve DEX literal identity")
        }
    }

    private fun smaliString(value: String): String = buildString {
        append('"')
        for (character in value) {
            when (character) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                in ' '..'~' -> append(character)
                else -> {
                    append("\\u")
                    append(character.code.toString(16).padStart(4, '0'))
                }
            }
        }
        append('"')
    }
}
