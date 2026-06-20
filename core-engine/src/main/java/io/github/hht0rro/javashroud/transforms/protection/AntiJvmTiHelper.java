package io.github.hht0rro.javashroud.transforms.protection;

public final class AntiJvmTiHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private AntiJvmTiHelper() { }
    public static native void nativeCheckJvmTiAgents(String detectionMode, String response);
    public static void checkJvmTiAgents(String detectionMode, String response) {
        if (!JniMicrokernelHelper.isNativeLoaded()) return;
        try {
            nativeCheckJvmTiAgents(detectionMode, response);
        } catch (UnsatisfiedLinkError | SecurityException ignored) {
        }
    }
}
