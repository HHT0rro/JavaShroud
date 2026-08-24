package io.github.hht0rro.javashroud.capabilities

/**
 * The current protected-artifact format has no standalone loader-protection
 * passes. Class and delayed-method payload formats were retired in favour of
 * the unified AKEN/VBC4 native route.
 */
internal fun loaderProtectionCapabilityBindings(): List<CapabilityBinding> = emptyList()

fun buildLoaderProtectionCapabilityDefinitions() = capabilityDefinitions(loaderProtectionCapabilityBindings())