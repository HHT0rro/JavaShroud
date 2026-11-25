package io.github.hht0rro.javashroud.transforms.protection.qp

/**
 * Current-format Qp VM material dimensions.
 *
 * This is deliberately a small protocol constant holder rather than an
 * evaluator or recovery helper.  Page material is consumed by the bound
 * Qp VM compiler and the transient native schedule; no split/recovery API is
 * exposed from the build engine.
 */
internal object QpMethodMaterial {
    const val PAGE_MATERIAL_SIZE: Int = 32
}
