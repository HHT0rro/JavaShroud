package io.github.hht0rro.javashroud.transforms.protection;

public final class AntiByteBuddyHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private AntiByteBuddyHelper() { }
    public static native void nativeCheckByteBuddy(String response);
    public static void checkByteBuddy(String response) {
        if (!JniMicrokernelHelper.isNativeLoaded()) return;
        try {
            nativeCheckByteBuddy(response);
        } catch (UnsatisfiedLinkError | SecurityException ignored) {
        }
    }
}
