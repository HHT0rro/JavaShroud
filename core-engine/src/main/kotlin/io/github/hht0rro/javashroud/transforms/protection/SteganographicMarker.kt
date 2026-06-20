package io.github.hht0rro.javashroud.transforms.protection

/**
 * Steganographic marker annotation.
 * Used to embed metadata in class annotations.
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS)
annotation class SteganographicMarker(val value: String)
