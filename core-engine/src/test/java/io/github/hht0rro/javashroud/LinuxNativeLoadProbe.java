package io.github.hht0rro.javashroud;

/**
 * WSL/Linux probe that loads the locked glibc 2.17 cdylib and exercises the
 * source-named JNI initialization boundary after {@code j.l} recovery.
 */
public final class LinuxNativeLoadProbe {
    private LinuxNativeLoadProbe() {}

    static native int nativeInit(String platform);

    static native int nativeHeartbeat();

    static native boolean nativeInstallSessionNonce(byte[] startupNonce);

    static native int nativeInstallCatalog(byte[] directory, byte[] bundle);

    static native Object nativeExecuteVmPage(long entryToken, byte[] packedRequest, Object[] args);

    static native String nativeOpenStringPage(byte[] packedRequest);

    static native byte[] nativeReadClassPage(byte[] packedRequest);

    static native void nativeConsumeNativeSegment(byte[] packedRequest);

    static native int nativeInitializeDefense(String surface, String profile);

    static native int nativeProbeDefense(String surface, String point);

    static native byte[] nativeTransformDefense(byte[] material, String binding);

    static native byte[] nativeOpenTargetToken(byte[] token, String callerOwner, String indyName, String methodType);

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: LinuxNativeLoadProbe <libqp_ffi.so>");
            System.exit(2);
        }
        System.setProperty("j.l", "io/github/hht0rro/javashroud/LinuxNativeLoadProbe");
        System.setProperty("j.m", bindingMap());
        System.load(args[0]);
        System.out.println("INIT=" + nativeInit("linux-x64"));
        System.out.println("BEAT=" + nativeHeartbeat());
        byte[] nonce = new byte[32];
        new java.security.SecureRandom().nextBytes(nonce);
        try {
            if (!nativeInstallSessionNonce(nonce)) {
                System.err.println("native session install failed");
                System.exit(3);
            }
        } finally {
            java.util.Arrays.fill(nonce, (byte) 0);
        }
        System.out.println("SESSION=ok");
        try {
            nativeOpenStringPage(new byte[29]);
            System.err.println("unbound page unexpectedly opened");
            System.exit(4);
        } catch (SecurityException expected) {
            System.out.println("UNBOUND=ok");
        }
    }

    private static String bindingMap() {
        String owner = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge";
        String[][] methods = {
                {"nativeInit", "(Ljava/lang/String;)I", "nativeInit"},
                {"nativeHeartbeat", "()I", "nativeHeartbeat"},
                {"nativeInstallSessionNonce", "([B)Z", "nativeInstallSessionNonce"},
                {"nativeInstallCatalog", "([B[B)I", "nativeInstallCatalog"},
                {"nativeExecuteVmPage", "(J[B[Ljava/lang/Object;)Ljava/lang/Object;", "nativeExecuteVmPage"},
                {"nativeOpenStringPage", "([B)Ljava/lang/String;", "nativeOpenStringPage"},
                {"nativeReadClassPage", "([B)[B", "nativeReadClassPage"},
                {"nativeConsumeNativeSegment", "([B)V", "nativeConsumeNativeSegment"},
                {"nativeInitializeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeInitializeDefense"},
                {"nativeProbeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeProbeDefense"},
                {"nativeTransformDefense", "([BLjava/lang/String;)[B", "nativeTransformDefense"},
                {"nativeOpenTargetToken", "([BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)[B", "nativeOpenTargetToken"},
        };
        StringBuilder result = new StringBuilder();
        for (String[] method : methods) {
            try {
                byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(("QP-BINDING-V1|" + owner + "#" + method[0] + "#" + method[1])
                                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                for (int i = 0; i < 8; i++) result.append(String.format("%02x", digest[i] & 0xff));
            } catch (java.security.NoSuchAlgorithmException error) {
                throw new IllegalStateException(error);
            }
            result.append('=').append(method[2]).append('\n');
        }
        return result.toString();
    }

}
