package io.github.hht0rro.javashroud;

/**
 * WSL/Linux probe that loads the locked glibc 2.17 cdylib and exercises the
 * source-named R1 JNI surface after {@code j.l} recovery.
 */
public final class LinuxR1LoadProbe {
    private LinuxR1LoadProbe() {}

    static native int nativeInit(String platform);

    static native int nativeHeartbeat();

    static native boolean nativeInstallAkenSessionNonce(byte[] startupNonce);

    static native int nativeInstallAkenCatalog(byte[] directory, byte[] bundle);

    static native Object nativeExecuteAkenVmPage(
            long entryToken,
            byte[] encodedHandle,
            int pageIndex,
            byte[] callSiteProof,
            Object[] args
    );

    static native String nativeOpenAkenString(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native byte[] nativeReadAkenClassPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native void nativeConsumeAkenNativeChunk(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native int nativeInitializeDefense(String surface, String profile);

    static native int nativeProbeDefense(String surface, String point);

    static native byte[] nativeTransformDefense(byte[] material, String binding);

    public static void main(String[] args) {
        if (args.length < 1 || args.length > 2) {
            System.err.println("usage: LinuxR1LoadProbe <libjsrt_ffi.so> [catalog-sidecar]");
            System.exit(2);
        }
        System.setProperty("j.l", "io/github/hht0rro/javashroud/LinuxR1LoadProbe");
        System.setProperty("j.m", bindingMap());
        if (args.length == 2) {
            System.setProperty("j.c", args[1]);
        }
        System.load(args[0]);
        System.out.println("INIT=" + nativeInit("linux-x64"));
        System.out.println("BEAT=" + nativeHeartbeat());
        if (args.length == 2) {
            System.out.println("STR=" + nativeOpenAkenString(readAll("page-3.handle"), 3, readAll("page-3.proof")));
            System.out.println("CLS=" + new String(nativeReadAkenClassPage(readAll("page-4.handle"), 4, readAll("page-4.proof"))));
            nativeConsumeAkenNativeChunk(readAll("page-5.handle"), 5, readAll("page-5.proof"));
            System.out.println("NAT=ok");
            System.out.println("VM=" + nativeExecuteAkenVmPage(0L, readAll("page-6.handle"), 6, readAll("page-6.proof"), null));
        }
    }

    private static String bindingMap() {
        String owner = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper";
        String[][] methods = {
                {"nativeInit", "(Ljava/lang/String;)I", "nativeInit"},
                {"nativeHeartbeat", "()I", "nativeHeartbeat"},
                {"nativeInstallAkenSessionNonce", "([B)Z", "nativeInstallAkenSessionNonce"},
                {"nativeInstallAkenCatalog", "([B[B)I", "nativeInstallAkenCatalog"},
                {"nativeExecuteAkenVmPage", "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;", "nativeExecuteAkenVmPage"},
                {"nativeOpenAkenString", "([BI[B)Ljava/lang/String;", "nativeOpenAkenString"},
                {"nativeReadAkenClassPage", "([BI[B)[B", "nativeReadAkenClassPage"},
                {"nativeConsumeAkenNativeChunk", "([BI[B)V", "nativeConsumeAkenNativeChunk"},
                {"nativeInitializeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeInitializeDefense"},
                {"nativeProbeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeProbeDefense"},
                {"nativeTransformDefense", "([BLjava/lang/String;)[B", "nativeTransformDefense"},
        };
        StringBuilder result = new StringBuilder();
        for (String[] method : methods) {
            try {
                byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(("AKEN-BINDING-V1|" + owner + "#" + method[0] + "#" + method[1])
                                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                for (int i = 0; i < 8; i++) result.append(String.format("%02x", digest[i] & 0xff));
            } catch (java.security.NoSuchAlgorithmException error) {
                throw new IllegalStateException(error);
            }
            result.append('=').append(method[2]).append('\n');
        }
        return result.toString();
    }

    private static byte[] readAll(String name) {
        String root = System.getProperty("j.c");
        try {
            return java.nio.file.Files.readAllBytes(java.nio.file.Path.of(root, name));
        } catch (Exception error) {
            throw new IllegalStateException(name, error);
        }
    }
}
