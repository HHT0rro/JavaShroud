package io.github.hht0rro.javashroud.model.config

/** Hard ceilings vs the unprotected/protected baseline for RELEASE_HARDENED. */
object HardenedPerfBudget {
    const val STARTUP_MULTIPLIER: Double = 2.0
    const val ARTIFACT_SIZE_MULTIPLIER: Double = 2.0
    const val CALL_OVERHEAD_MULTIPLIER: Double = 3.0
}
