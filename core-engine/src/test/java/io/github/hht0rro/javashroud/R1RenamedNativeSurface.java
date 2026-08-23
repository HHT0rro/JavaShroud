package io.github.hht0rro.javashroud;

/**
 * Sealed-helper stand-in used to prove AKEN-R1 RegisterNatives recovery after
 * method renaming. JNI_OnLoad reads {@code j.l}/{@code j.m} and binds these
 * short names instead of the source {@code nativeInit} surface.
 */
final class R1RenamedNativeSurface {
    private R1RenamedNativeSurface() {}

    static native int nInit(String platform);

    static native int nBeat();

    static native boolean nNonce(byte[] startupNonce);

    static native Object nVm(long entryToken, byte[] encodedHandle, int pageIndex, byte[] callSiteProof, Object[] args);

    static native String nStr(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native byte[] nCls(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native void nNat(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);
}
