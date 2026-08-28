package io.github.hht0rro.javashroud.transforms.protection;
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge;

public final class ThreadContextKeyHelper {
    static { QpBridge.loadKernel("loader", "auto", "vm-diverse"); }
    private static volatile String contextSource = "thread-hash";
    private ThreadContextKeyHelper() { }
    static native void nativeInitializeContextKeys(String contextSource);
    static native byte[] nativeGetContextKey();

    public static void initializeContextKeys(String source) {
        contextSource = source == null ? "thread-hash" : source;
        if (!QpBridge.isNativeLoaded()) {
            throw new SecurityException("thread context key init requires the sealed native kernel");
        }
        nativeInitializeContextKeys(contextSource);
    }

    public static byte[] getContextKey() {
        if (!QpBridge.isNativeLoaded()) {
            throw new SecurityException("thread context key requires the sealed native kernel");
        }
        return nativeGetContextKey();
    }
}