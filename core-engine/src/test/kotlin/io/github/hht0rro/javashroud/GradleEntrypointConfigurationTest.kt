package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class GradleEntrypointConfigurationTest {

    @Test
    fun application_run_task_is_never_up_to_date_so_schema_stdout_is_emitted() {
        val buildFile = generateSequence(Path.of("").toAbsolutePath().normalize()) { it.parent }
            .map { it.resolve(Path.of("core-engine", "build.gradle.kts")) }
            .first { Files.exists(it) }
        val text = Files.readString(buildFile)

        assertTrue(
            text.contains("tasks.named<JavaExec>(\"run\")") && text.contains("outputs.upToDateWhen { false }"),
            "core-engine run task must always execute so :core-engine:run --args=\"-schema\" emits schema stdout",
        )
    }
}
