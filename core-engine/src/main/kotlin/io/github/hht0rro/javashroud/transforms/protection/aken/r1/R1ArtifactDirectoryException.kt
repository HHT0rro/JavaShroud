package io.github.hht0rro.javashroud.transforms.protection.aken.r1

/** Strict failure reported by the current AKEN-R1 artifact-directory codec. */
class R1ArtifactDirectoryException(
    val code: Code,
    message: String,
) : IllegalArgumentException(message) {
    enum class Code {
        INVALID_INPUT,
        INVALID_MAGIC,
        TRUNCATED,
        TRAILING_BYTES,
        LENGTH_OVERFLOW,
        FIELD_TOO_LARGE,
        UNSUPPORTED_TARGET,
        INVALID_PATH,
        DUPLICATE_KEY,
        NON_CANONICAL_ORDER,
        AUTHENTICATION_FAILED,
        RUNTIME_BINDING_MISMATCH,
    }

    companion object {
        internal fun fail(code: Code, message: String): Nothing =
            throw R1ArtifactDirectoryException(code, message)
    }
}
