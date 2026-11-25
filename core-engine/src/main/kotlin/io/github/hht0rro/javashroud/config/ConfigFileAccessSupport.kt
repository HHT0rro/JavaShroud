package io.github.hht0rro.javashroud.config

import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile

fun ensureReadableFile(path: Path) {
    if (!path.exists()) {
        throw IllegalArgumentException("File does not exist: path=${path.absolutePathString()}")
    }

    if (!path.isRegularFile()) {
        throw IllegalArgumentException("Path is not a file: path=${path.absolutePathString()}")
    }
}
