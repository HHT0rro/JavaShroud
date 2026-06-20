package io.github.hht0rro.javashroud.transforms.protection;

public final class EnvironmentBindingHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private EnvironmentBindingHelper() { }
    static native String nativeDeriveKey(String bindingSource, String salt);
    static native void nativeVerifyEnvironment(String expectedToken, String bindingSource, String salt);

    public static String deriveKey(String bindingSource, String salt) {
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("environment-bound key derivation requires the sealed native kernel; no Java fallback");
        }
        return nativeDeriveKey(bindingSource, salt);
    }

    public static void verifyEnvironment(String expectedToken, String bindingSource, String salt) {
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("environment binding verification requires the sealed native kernel; no Java fallback");
        }
        nativeVerifyEnvironment(expectedToken, bindingSource, salt);
    }
}