package io.github.hht0rro.javashroud.transforms.protection;

/**
 * Runtime helper for anti-dump enforcement.
 * Sensitive logic delegated to native js_kernel library.
 */
public final class AntiDumpRuntimeHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private AntiDumpRuntimeHelper() { }

    public static native void nativeInitializeProtection(String protectionLevel);

    public static void initializeProtection(String protectionLevel) {
        if (!JniMicrokernelHelper.isNativeLoaded()) return;
        try {
            nativeInitializeProtection(protectionLevel);
        } catch (UnsatisfiedLinkError | SecurityException ignored) {
        }
    }
}
