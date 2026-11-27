package io.github.hht0rro.javashroud;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

/**
 * Current-ABI stand-in for an unauthenticated relocated helper. A loader-only
 * runtime must reject its plaintext binding map before registering these methods.
 */
final class RenamedNativeSurface {
    private RenamedNativeSurface() {}

    static native int nInit(String platform);

    static native int nBeat();

    static native boolean nNonce(byte[] startupNonce);

    static native int nCatalog(byte[] directory, byte[] bundle, byte[] pack);

    static native Object nVm(String sealedEntryToken, byte[] packedRequest, Object[] args);

    static native String nStr(byte[] packedRequest);

    static native byte[] nCls(byte[] packedRequest);

    static native void nNat(byte[] packedRequest);

    static native int nDefenseInit(String surface, String profile);

    static native int nDefenseProbe(String surface, String point);

    static native byte[] nDefenseTransform(byte[] material, String binding);

    static native int nDefenseInitCode(int surfaceCode, int profileCode);

    static native int nDefenseProbeCode(int surfaceCode, int pointCode);

    static native byte[] nDefenseTransformCode(byte[] material, int bindingCode);

    static native Object nInvokeSite(
            MethodHandles.Lookup lookup,
            String indyName,
            MethodType methodType,
            byte[] token,
            Object[] arguments,
            boolean linkBootstrap);
}
