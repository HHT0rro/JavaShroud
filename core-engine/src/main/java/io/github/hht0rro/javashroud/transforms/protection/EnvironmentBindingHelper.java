package io.github.hht0rro.javashroud.transforms.protection;

public final class EnvironmentBindingHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private EnvironmentBindingHelper() { }
    static native String nativeDeriveKey(String bindingSource, String salt, String expectedFingerprint);
    static native void nativeVerifyEnvironment(String expectedToken, String bindingSource, String salt, String expectedFingerprint);
    static native String nativeGetMachineFingerprint();

    public static String deriveKey(String bindingSource, String salt, String expectedFingerprint) {
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("environment-bound key derivation requires the sealed native kernel");
        }
        return nativeDeriveKey(bindingSource, salt, expectedFingerprint);
    }

    public static void verifyEnvironment(String expectedToken, String bindingSource, String salt, String expectedFingerprint) {
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("environment binding verification requires the sealed native kernel");
        }
        nativeVerifyEnvironment(expectedToken, bindingSource, salt, expectedFingerprint);
    }

    public static String getMachineFingerprint() {
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("machine fingerprint requires the sealed native kernel");
        }
        return nativeGetMachineFingerprint();
    }
}
