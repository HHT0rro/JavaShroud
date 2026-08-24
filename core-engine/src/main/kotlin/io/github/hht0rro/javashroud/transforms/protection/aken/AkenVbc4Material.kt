package io.github.hht0rro.javashroud.transforms.protection.aken

/**
 * Current-format VBC4 material dimensions.
 *
 * This is deliberately a small protocol constant holder rather than an
 * evaluator or recovery helper.  Page material is consumed by the bound
 * VBC4 compiler and the transient native schedule; no split/recovery API is
 * exposed from the build engine.
 */
internal object AkenVbc4Material {
    const val PAGE_MATERIAL_SIZE: Int = 32
}
