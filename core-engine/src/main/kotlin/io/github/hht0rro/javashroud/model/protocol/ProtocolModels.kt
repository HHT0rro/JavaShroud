package io.github.hht0rro.javashroud.model.protocol

enum class EngineEventType {
    PROGRESS,
    LOG,
    DONE,
    ERROR,
}

enum class EngineEventLevel {
    INFO,
    WARN,
    ERROR,
    SUCCESS,
}

data class EngineEvent(
    val level: String,
    val type: String,
    val message: String,
    val progress: Int?,
    val outPath: String?,
)
