package io.github.hht0rro.javashroud.transforms.protection;

public final class StringEncryptionHelper {
    static { JniMicrokernelHelper.loadKernel("decrypt", "auto", "vm-diverse"); }

    private StringEncryptionHelper() { }

    public static native byte[] nativeDecodeString(byte[] payload, int seed, int flags);
}