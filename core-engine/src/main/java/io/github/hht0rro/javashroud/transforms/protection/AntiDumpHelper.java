package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

public final class AntiDumpHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private AntiDumpHelper() { }
    static native String nativeBuildString(byte[] encodedBytes);
    static native String nativeBuildStringFromB64(String encodedB64);
    static native String nativeDecodeString(String encoded);
    public static String buildString(MethodHandles.Lookup lookup, String name, MethodType type, byte[] encodedBytes) {
        if (JniMicrokernelHelper.isNativeLoaded()) {
            try {
                return nativeBuildString(encodedBytes);
            } catch (UnsatisfiedLinkError | SecurityException e) {
                throw new SecurityException("anti-dump native string build failed", e);
            }
        }
        throw new SecurityException("anti-dump string protection requires the sealed native kernel");
    }
    public static String buildStringFromB64(MethodHandles.Lookup lookup, String name, MethodType type, String encodedB64) {
        return decodeString(encodedB64);
    }
    public static String buildStringFromB64Condy(MethodHandles.Lookup lookup, String name, Class type, String encodedB64) {
        return decodeString(encodedB64);
    }
    public static String decodeString(String encoded) {
        if (JniMicrokernelHelper.isNativeLoaded()) {
            try {
                return nativeDecodeString(encoded);
            } catch (UnsatisfiedLinkError | SecurityException e) {
                throw new SecurityException("anti-dump native string decode failed", e);
            }
        }
        throw new SecurityException("anti-dump string decode requires the sealed native kernel");
    }
}
