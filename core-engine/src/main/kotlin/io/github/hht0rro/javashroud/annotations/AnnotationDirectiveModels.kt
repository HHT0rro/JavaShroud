package io.github.hht0rro.javashroud.annotations

internal enum class AnnotationTargetKind {
    CLASS,
    METHOD,
    FIELD,
}

internal data class AnnotationDirective(
    val target: String,
    val targetKind: AnnotationTargetKind,
    val passId: String,
    val enabled: Boolean,
    val options: Map<String, String>,
)

internal const val JAVA_SHROUD_PASS_DESCRIPTOR = "Lio/github/hht0rro/javashroud/annotations/JavaShroudPass;"
internal const val JAVA_SHROUD_PASSES_DESCRIPTOR = "Lio/github/hht0rro/javashroud/annotations/JavaShroudPasses;"
internal const val JAVA_SHROUD_OPTION_DESCRIPTOR = "Lio/github/hht0rro/javashroud/annotations/JavaShroudOption;"