package io.github.hht0rro.javashroud.transforms.protection;

public final class ThreadContextKeyHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private static volatile String contextSource = "thread-hash";
    private ThreadContextKeyHelper() { }
    static native void nativeInitializeContextKeys(String contextSource);
    static native byte[] nativeGetContextKey();

    public static void initializeContextKeys(String source) {
        contextSource = source == null ? "thread-hash" : source;
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("thread context key init requires the sealed native kernel; no Java fallback");
        }
        nativeInitializeContextKeys(contextSource);
    }

    public static byte[] getContextKey() {
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("thread context key requires the sealed native kernel; no Java fallback");
        }
        return nativeGetContextKey();
    }
}