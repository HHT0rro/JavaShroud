package io.github.hht0rro.javashroud.transforms.protection;

import java.util.Base64;
import java.util.concurrent.CopyOnWriteArrayList;

public final class CrossClassCouplingHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private static final CopyOnWriteArrayList<byte[]> FRAGMENTS = new CopyOnWriteArrayList<>();
    private CrossClassCouplingHelper() { }
    static native void nativeRegisterFragment(String fragmentBase64, String className);
    static native byte[] nativeReconstructKey();

    public static void registerFragment(String fragmentBase64, String className) {
        if (JniMicrokernelHelper.isNativeLoaded()) {
            try {
                nativeRegisterFragment(fragmentBase64, className);
                return;
            } catch (UnsatisfiedLinkError | SecurityException ignored) {
            }
        }
        if (fragmentBase64 != null) FRAGMENTS.add(Base64.getDecoder().decode(fragmentBase64));
    }

    public static byte[] reconstructKey() {
        if (JniMicrokernelHelper.isNativeLoaded()) {
            try {
                return nativeReconstructKey();
            } catch (UnsatisfiedLinkError | SecurityException ignored) {
            }
        }
        if (FRAGMENTS.size() < 2) return null;
        byte[] key = new byte[FRAGMENTS.get(0).length];
        for (int i = 0; i < FRAGMENTS.size(); i++) {
            byte[] fragment = FRAGMENTS.get(i);
            for (int j = 0; j < key.length && j < fragment.length; j++) {
                key[j] = (byte) (key[j] ^ fragment[j] ^ (byte) (i * 37 + j));
            }
        }
        return key;
    }
}
